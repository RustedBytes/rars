use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;

const HASH_ROUNDS: u32 = 0x40000;

pub struct Rar30Cipher {
    cipher: Aes128,
    iv: [u8; 16],
}

impl Rar30Cipher {
    pub fn new(password: &[u8], salt: Option<[u8; 8]>) -> Self {
        let (key, iv) = derive_key_iv(password, salt);
        Self {
            cipher: Aes128::new(&key.into()),
            iv,
        }
    }

    pub fn decrypt_in_place(&mut self, data: &mut [u8]) {
        for block in data.chunks_exact_mut(16) {
            self.decrypt_block(block);
        }
    }

    pub fn decrypt_block(&mut self, block: &mut [u8]) {
        let ciphertext: [u8; 16] = block.try_into().expect("AES block size");
        self.cipher.decrypt_block(block.into());
        for (byte, iv_byte) in block.iter_mut().zip(self.iv) {
            *byte ^= iv_byte;
        }
        self.iv = ciphertext;
    }
}

fn derive_key_iv(password: &[u8], salt: Option<[u8; 8]>) -> ([u8; 16], [u8; 16]) {
    let mut raw = Vec::with_capacity(password.len() * 2 + 8);
    let password = String::from_utf8_lossy(password);
    for code_unit in password.encode_utf16() {
        raw.extend_from_slice(&code_unit.to_le_bytes());
    }
    if let Some(salt) = salt {
        raw.extend_from_slice(&salt);
    }

    let mut sha1 = Sha1::new();
    let mut iv = [0; 16];
    for i in 0..HASH_ROUNDS {
        sha1.update_rar29(&mut raw);
        sha1.update(&[
            (i & 0xff) as u8,
            ((i >> 8) & 0xff) as u8,
            ((i >> 16) & 0xff) as u8,
        ]);
        if i % (HASH_ROUNDS / 16) == 0 {
            let digest = sha1.clone().finish_words();
            iv[(i / (HASH_ROUNDS / 16)) as usize] = digest[4] as u8;
        }
    }

    let digest = sha1.finish_words();
    let mut key = [0; 16];
    for (i, word) in digest[..4].iter().enumerate() {
        key[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    (key, iv)
}

#[derive(Clone)]
struct Sha1 {
    state: [u32; 5],
    len: u64,
    buffer: [u8; 64],
    buffer_len: usize,
}

impl Sha1 {
    fn new() -> Self {
        Self {
            state: [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
            ],
            len: 0,
            buffer: [0; 64],
            buffer_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut data = data;
        self.len += data.len() as u64;

        if self.buffer_len != 0 {
            let take = (64 - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];
            if self.buffer_len == 64 {
                sha1_transform(&mut self.state, &self.buffer, None);
                self.buffer_len = 0;
            }
        }

        while data.len() >= 64 {
            sha1_transform(&mut self.state, &data[..64], None);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    fn update_rar29(&mut self, data: &mut [u8]) {
        self.len += data.len() as u64;
        let mut offset = 0;

        if self.buffer_len != 0 {
            let take = (64 - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            offset += take;
            if self.buffer_len == 64 {
                sha1_transform(&mut self.state, &self.buffer, None);
                self.buffer_len = 0;
            }
        }

        while offset + 64 <= data.len() {
            let block = &mut data[offset..offset + 64];
            let mut input = [0; 64];
            input.copy_from_slice(block);
            sha1_transform(&mut self.state, &input, Some(block));
            offset += 64;
        }

        let remaining = data.len() - offset;
        if remaining != 0 {
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    fn finish_words(mut self) -> [u32; 5] {
        let bit_len = self.len * 8;
        self.update(&[0x80]);
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            sha1_transform(&mut self.state, &self.buffer, None);
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sha1_transform(&mut self.state, &self.buffer, None);
        self.state
    }
}

fn sha1_transform(state: &mut [u32; 5], block: &[u8], writeback: Option<&mut [u8]>) {
    let mut w = [0u32; 80];
    for (i, chunk) in block.chunks_exact(4).take(16).enumerate() {
        w[i] = u32::from_be_bytes(chunk.try_into().expect("SHA-1 word size"));
    }
    if let Some(writeback) = writeback {
        for (i, word) in w[..16].iter().enumerate() {
            writeback[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (i, word) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(*word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}
