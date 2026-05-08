//! Shared RAR CRC-32 primitives.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc32 {
    value: u32,
}

impl Crc32 {
    pub const fn new() -> Self {
        Self { value: 0xffff_ffff }
    }

    pub fn update(&mut self, input: &[u8]) {
        for &byte in input {
            self.value = update_raw_byte(self.value, byte);
        }
    }

    pub fn update_zeroes(&mut self, len: u64) {
        let mut matrix = zero_byte_matrix();
        let mut count = len;
        while count != 0 {
            if count & 1 != 0 {
                self.value = gf2_matrix_times(&matrix, self.value);
            }
            count >>= 1;
            if count != 0 {
                matrix = gf2_matrix_square(&matrix);
            }
        }
    }

    pub const fn finish(self) -> u32 {
        !self.value
    }
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn crc32(input: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(input);
    crc.finish()
}

pub fn crc32_raw(input: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff;
    for &byte in input {
        crc = update_raw_byte(crc, byte);
    }
    crc
}

pub fn table_entry(index: u8) -> u32 {
    TABLE[index as usize]
}

fn update_raw_byte(crc: u32, byte: u8) -> u32 {
    (crc >> 8) ^ table_entry((crc as u8) ^ byte)
}

fn zero_byte_matrix() -> [u32; 32] {
    let mut matrix = [0; 32];
    for (bit, slot) in matrix.iter_mut().enumerate() {
        let mut value = 1u32 << bit;
        let index = value as u8;
        value = (value >> 8) ^ table_entry(index);
        *slot = value;
    }
    matrix
}

fn gf2_matrix_times(matrix: &[u32; 32], mut vector: u32) -> u32 {
    let mut sum = 0;
    let mut index = 0;
    while vector != 0 {
        if vector & 1 != 0 {
            sum ^= matrix[index];
        }
        vector >>= 1;
        index += 1;
    }
    sum
}

fn gf2_matrix_square(matrix: &[u32; 32]) -> [u32; 32] {
    let mut square = [0; 32];
    for (index, slot) in square.iter_mut().enumerate() {
        *slot = gf2_matrix_times(matrix, matrix[index]);
    }
    square
}

const TABLE: [u32; 256] = crc32_table();

const fn crc32_table() -> [u32; 256] {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut value = i as u32;
        let mut bit = 0;
        while bit < 8 {
            let mask = 0u32.wrapping_sub(value & 1);
            value = (value >> 1) ^ (0xedb8_8320 & mask);
            bit += 1;
        }
        table[i] = value;
        i += 1;
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn raw_crc_matches_unfinalized_seeded_rar15_value() {
        assert_eq!(crc32_raw(b"password"), 0xca3d_b92a);
    }

    #[test]
    fn update_zeroes_matches_byte_update() {
        let mut skipped = Crc32::new();
        skipped.update(b"prefix");
        skipped.update_zeroes(1024);
        skipped.update(b"suffix");

        let mut bytewise = Crc32::new();
        bytewise.update(b"prefix");
        bytewise.update(&[0; 1024]);
        bytewise.update(b"suffix");

        assert_eq!(skipped.finish(), bytewise.finish());
    }

    #[test]
    fn table_entry_matches_bitwise_generation() {
        assert_eq!(table_entry(0), 0);
        assert_eq!(table_entry(1), 0x7707_3096);
        assert_eq!(table_entry(0xff), 0x2d02_ef8d);
    }
}
