use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use sha1::{Digest, Sha1 as FastSha1};
use std::str;

const HASH_ROUNDS: u32 = 0x40000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    NonUtf8Password,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct Rar30Cipher {
    cipher: Aes128,
    iv: [u8; 16],
}

impl Rar30Cipher {
    pub fn new(password: &[u8], salt: Option<[u8; 8]>) -> Result<Self> {
        let (key, iv) = derive_key_iv(password, salt)?;
        Ok(Self {
            cipher: Aes128::new(&key.into()),
            iv,
        })
    }

    pub fn decrypt_in_place(&mut self, data: &mut [u8]) {
        for block in data.chunks_exact_mut(16) {
            self.decrypt_block(block);
        }
    }

    pub fn encrypt_in_place(&mut self, data: &mut [u8]) {
        for block in data.chunks_exact_mut(16) {
            self.encrypt_block(block);
        }
    }

    fn encrypt_block(&mut self, block: &mut [u8]) {
        for (byte, iv_byte) in block.iter_mut().zip(self.iv) {
            *byte ^= iv_byte;
        }
        self.cipher.encrypt_block(block.into());
        self.iv.copy_from_slice(block);
    }

    fn decrypt_block(&mut self, block: &mut [u8]) {
        let ciphertext: [u8; 16] = block.try_into().expect("AES block size");
        self.cipher.decrypt_block(block.into());
        for (byte, iv_byte) in block.iter_mut().zip(self.iv) {
            *byte ^= iv_byte;
        }
        self.iv = ciphertext;
    }
}

fn derive_key_iv(password: &[u8], salt: Option<[u8; 8]>) -> Result<([u8; 16], [u8; 16])> {
    let mut raw = Vec::with_capacity(password.len() * 2 + 8);
    let password = str::from_utf8(password).map_err(|_| Error::NonUtf8Password)?;
    for code_unit in password.encode_utf16() {
        raw.extend_from_slice(&code_unit.to_le_bytes());
    }
    if let Some(salt) = salt {
        raw.extend_from_slice(&salt);
    }

    if raw.len() < 64 {
        return Ok(derive_key_iv_fast(&raw));
    }

    Ok(derive_key_iv_slow(&mut raw))
}

fn derive_key_iv_slow(raw: &mut [u8]) -> ([u8; 16], [u8; 16]) {
    let mut sha1 = Sha1::new();
    let mut iv = [0; 16];
    for i in 0..HASH_ROUNDS {
        sha1.update_rar29(raw);
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

fn derive_key_iv_fast(raw: &[u8]) -> ([u8; 16], [u8; 16]) {
    let mut sha1 = FastSha1::new();
    let mut iv = [0; 16];
    for i in 0..HASH_ROUNDS {
        sha1.update(raw);
        sha1.update([
            (i & 0xff) as u8,
            ((i >> 8) & 0xff) as u8,
            ((i >> 16) & 0xff) as u8,
        ]);
        if i % (HASH_ROUNDS / 16) == 0 {
            let digest = sha1.clone().finalize();
            iv[(i / (HASH_ROUNDS / 16)) as usize] = digest[19];
        }
    }

    let digest = sha1.finalize();
    let mut key = [0; 16];
    for (word_index, chunk) in digest[..16].chunks_exact(4).enumerate() {
        key[word_index * 4..word_index * 4 + 4]
            .copy_from_slice(&[chunk[3], chunk[2], chunk[1], chunk[0]]);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_kdf_material(password: &[u8], salt: Option<[u8; 8]>) -> Vec<u8> {
        let mut raw = Vec::with_capacity(password.len() * 2 + 8);
        let password = str::from_utf8(password).unwrap();
        for code_unit in password.encode_utf16() {
            raw.extend_from_slice(&code_unit.to_le_bytes());
        }
        if let Some(salt) = salt {
            raw.extend_from_slice(&salt);
        }
        raw
    }

    #[test]
    fn rar30_aes_encrypt_decrypt_round_trips_blocks() {
        let salt = Some([1, 2, 3, 4, 5, 6, 7, 8]);
        let mut data = *b"0123456789abcdefRAR AES CBC data";
        let plain = data;

        Rar30Cipher::new(b"password", salt)
            .unwrap()
            .encrypt_in_place(&mut data);
        assert_eq!(
            data,
            [
                0x5e, 0x59, 0xce, 0xa1, 0x16, 0xca, 0xa2, 0x1d, 0x4d, 0xc5, 0x05, 0xeb, 0xa9, 0x3f,
                0x7b, 0xcd, 0x0d, 0x04, 0xff, 0xea, 0x60, 0x67, 0x3d, 0xaf, 0x6a, 0x8f, 0x02, 0xb2,
                0x03, 0xc8, 0x7d, 0xde,
            ]
        );

        Rar30Cipher::new(b"password", salt)
            .unwrap()
            .decrypt_in_place(&mut data);
        assert_eq!(data, plain);
    }

    #[test]
    fn rar30_aes_round_trips_with_long_password_slow_path() {
        // Password long enough that utf-16(password) + 8-byte salt >= 64,
        // forcing derive_key_iv to use the custom Sha1 with update_rar29
        // instead of derive_key_iv_fast.
        let password = b"this-password-is-deliberately-long-enough-to-exceed-64-bytes-utf16";
        let salt = Some(*b"longsalt");
        let mut data = *b"0123456789abcdefRAR AES CBC data";
        let plain = data;

        Rar30Cipher::new(password, salt)
            .unwrap()
            .encrypt_in_place(&mut data);
        assert_ne!(data, plain);

        Rar30Cipher::new(password, salt)
            .unwrap()
            .decrypt_in_place(&mut data);
        assert_eq!(data, plain);
    }

    #[test]
    fn rejects_non_utf8_passwords() {
        assert!(matches!(
            Rar30Cipher::new(b"\xffpassword", None),
            Err(Error::NonUtf8Password)
        ));
    }

    #[test]
    fn rar30_fast_kdf_matches_reference_path_for_short_material() {
        for (password, salt) in [
            (b"".as_slice(), None),
            (b"password".as_slice(), Some(*b"rarsalt!")),
            ("páss".as_bytes(), Some([1, 2, 3, 4, 5, 6, 7, 8])),
        ] {
            let raw = raw_kdf_material(password, salt);
            assert!(
                raw.len() < 64,
                "case should exercise the fast-path precondition"
            );

            let fast = derive_key_iv_fast(&raw);
            let mut reference_raw = raw.clone();
            let reference = derive_key_iv_slow(&mut reference_raw);

            assert_eq!(fast, reference);
        }
    }
}
