pub struct Rar13Cipher {
    key: [u8; 3],
}

impl Rar13Cipher {
    pub fn new(password: &[u8]) -> Self {
        let mut key = [0u8; 3];
        for &byte in password {
            key[0] = key[0].wrapping_add(byte);
            key[1] ^= byte;
            key[2] = key[2].wrapping_add(byte).rotate_left(1);
        }
        Self { key }
    }

    pub fn new_comment() -> Self {
        Self { key: [0, 7, 77] }
    }

    pub fn encrypt_in_place(mut self, data: &mut [u8]) {
        for byte in data {
            self.advance();
            *byte = byte.wrapping_add(self.key[0]);
        }
    }

    pub fn decrypt_in_place(mut self, data: &mut [u8]) {
        for byte in data {
            self.advance();
            *byte = byte.wrapping_sub(self.key[0]);
        }
    }

    fn advance(&mut self) {
        self.key[1] = self.key[1].wrapping_add(self.key[2]);
        self.key[0] = self.key[0].wrapping_add(self.key[1]);
    }
}
