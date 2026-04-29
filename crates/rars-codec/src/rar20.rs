use crate::{Error, Result};
use std::io::{Read, Write};

const MAIN_COUNT: usize = 298;
const OFFSET_COUNT: usize = 48;
const LENGTH_COUNT: usize = 28;
const LEVEL_COUNT: usize = 19;
const TABLE_COUNT: usize = MAIN_COUNT + OFFSET_COUNT + LENGTH_COUNT;
const MAX_HISTORY: usize = 1024 * 1024;
const INPUT_CHUNK: usize = 64 * 1024;

const LENGTH_BASES: [usize; LENGTH_COUNT] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];
const LENGTH_BITS: [u8; LENGTH_COUNT] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];
const OFFSET_BASES: [usize; OFFSET_COUNT] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
];
const OFFSET_BITS: [u8; OFFSET_COUNT] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
];
const SHORT_BASES: [usize; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SHORT_BITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

pub fn unpack20_decode(input: &[u8], output_size: usize) -> Result<Vec<u8>> {
    let mut decoder = Unpack20::new();
    decoder.decode_member(input, output_size)
}

#[derive(Debug, Clone)]
pub struct Unpack20 {
    bits: BitReader,
    levels: [u8; TABLE_COUNT],
    main: Huffman,
    offsets: Huffman,
    lengths: Huffman,
    old_offsets: [usize; 4],
    last_offset: usize,
    last_length: usize,
    pending_match: Option<(usize, usize)>,
    in_block: bool,
    output: Vec<u8>,
    base_offset: usize,
}

impl Unpack20 {
    pub fn new() -> Self {
        Self {
            bits: BitReader::new(),
            levels: [0; TABLE_COUNT],
            main: Huffman::empty(),
            offsets: Huffman::empty(),
            lengths: Huffman::empty(),
            old_offsets: [0; 4],
            last_offset: 0,
            last_length: 0,
            pending_match: None,
            in_block: false,
            output: Vec::new(),
            base_offset: 0,
        }
    }

    pub fn decode_member(&mut self, input: &[u8], output_size: usize) -> Result<Vec<u8>> {
        let start = self.current_pos();
        let target = start
            .checked_add(output_size)
            .ok_or(Error::InvalidData("RAR 2.0 output size overflows"))?;
        if !input.is_empty() {
            self.bits = BitReader::new();
        }
        self.bits.append(input);
        self.decode_until(target).map_err(|error| match error {
            Error::NeedMoreInput => Error::InvalidData("RAR 2.0 bitstream is truncated"),
            error => error,
        })?;
        let out = self.raw_range(start, target)?.to_vec();
        self.trim_history(target, target);
        Ok(out)
    }

    pub fn decode_member_to(
        &mut self,
        input: &[u8],
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        let decoded = self.decode_member(input, output_size)?;
        out.write_all(&decoded)
            .map_err(|_| Error::InvalidData("RAR 2.0 output write failed"))
    }

    pub fn decode_member_from_reader(
        &mut self,
        input: &mut impl Read,
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        let mut input_bytes = Vec::new();
        let mut buffer = [0u8; INPUT_CHUNK];
        loop {
            let read = input
                .read(&mut buffer)
                .map_err(|_| Error::InvalidData("RAR 2.0 input read failed"))?;
            if read == 0 {
                break;
            }
            input_bytes.extend_from_slice(&buffer[..read]);
        }
        self.decode_member_to(&input_bytes, output_size, out)
    }

    fn decode_until(&mut self, target: usize) -> Result<()> {
        while self.current_pos() < target {
            self.drain_pending_match(target)?;
            if self.current_pos() >= target {
                break;
            }
            if !self.in_block {
                self.read_tables()?;
                self.in_block = true;
            }
            self.decode_lz(target)?;
        }
        Ok(())
    }

    fn read_tables(&mut self) -> Result<()> {
        self.bits.align_byte();
        let bit_field = self.bits.peek_bits(16)?;
        let audio_block = bit_field & 0x8000 != 0;
        let keep_tables = bit_field & 0x4000 != 0;
        self.bits.read_bits(2)?;
        if audio_block {
            return Err(Error::InvalidData(
                "RAR 2.0 audio blocks are not implemented",
            ));
        }
        if !keep_tables {
            self.levels = [0; TABLE_COUNT];
        }

        let level_lengths = Self::read_level_lengths(&mut self.bits)?;
        let level_decoder = Huffman::from_lengths(&level_lengths)?;
        let mut new_levels = [0u8; TABLE_COUNT];
        let mut pos = 0usize;
        while pos < TABLE_COUNT {
            let symbol = level_decoder.decode(&mut self.bits)?;
            match symbol {
                0..=15 => {
                    new_levels[pos] = (self.levels[pos].wrapping_add(symbol as u8)) & 0x0f;
                    pos += 1;
                }
                16 => {
                    if pos == 0 {
                        return Err(Error::InvalidData("RAR 2.0 table repeat at start"));
                    }
                    let count = 3 + self.bits.read_bits(2)? as usize;
                    let value = new_levels[pos - 1];
                    fill_levels(&mut new_levels, &mut pos, count, value)?;
                }
                17 => {
                    let count = 3 + self.bits.read_bits(3)? as usize;
                    fill_levels(&mut new_levels, &mut pos, count, 0)?;
                }
                18 => {
                    let count = 11 + self.bits.read_bits(7)? as usize;
                    fill_levels(&mut new_levels, &mut pos, count, 0)?;
                }
                _ => return Err(Error::InvalidData("RAR 2.0 invalid level symbol")),
            }
        }

        self.levels = new_levels;
        self.main = Huffman::from_lengths(&self.levels[..MAIN_COUNT])?;
        self.offsets = Huffman::from_lengths(&self.levels[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT])?;
        self.lengths = Huffman::from_lengths(&self.levels[MAIN_COUNT + OFFSET_COUNT..])?;
        Ok(())
    }

    fn read_level_lengths(bits: &mut BitReader) -> Result<[u8; LEVEL_COUNT]> {
        let mut lengths = [0u8; LEVEL_COUNT];
        let mut pos = 0usize;
        while pos < LEVEL_COUNT {
            let value = bits.read_bits(4)? as u8;
            if value == 15 {
                let zero_count = bits.read_bits(4)? as usize;
                if zero_count == 0 {
                    lengths[pos] = 15;
                    pos += 1;
                } else {
                    pos = pos.saturating_add(zero_count + 2).min(LEVEL_COUNT);
                }
            } else {
                lengths[pos] = value;
                pos += 1;
            }
        }
        Ok(lengths)
    }

    fn decode_lz(&mut self, output_size: usize) -> Result<()> {
        while self.current_pos() < output_size {
            let symbol = self.main.decode(&mut self.bits)?;
            match symbol {
                0..=255 => self.output.push(symbol as u8),
                256 => {
                    if self.last_length != 0 {
                        self.copy_match(self.last_length, self.last_offset, output_size)?;
                    }
                }
                257..=260 => {
                    let index = symbol - 257;
                    let offset = self.old_offsets[index];
                    let length_slot = self.lengths.decode(&mut self.bits)?;
                    if length_slot >= LENGTH_COUNT {
                        return Err(Error::InvalidData("RAR 2.0 invalid repeat length slot"));
                    }
                    let mut length = LENGTH_BASES[length_slot] + 2;
                    if LENGTH_BITS[length_slot] != 0 {
                        length += self.bits.read_bits(LENGTH_BITS[length_slot])? as usize;
                    }
                    if offset >= 0x101 {
                        length += 1;
                    }
                    if offset >= 0x2000 {
                        length += 1;
                    }
                    if offset >= 0x40000 {
                        length += 1;
                    }
                    self.rotate_old_offset(index);
                    self.last_offset = offset;
                    self.last_length = length;
                    self.copy_match(length, offset, output_size)?;
                }
                261..=268 => {
                    let index = symbol - 261;
                    let mut offset = SHORT_BASES[index] + 1;
                    if SHORT_BITS[index] != 0 {
                        offset += self.bits.read_bits(SHORT_BITS[index])? as usize;
                    }
                    self.last_offset = offset;
                    self.last_length = 2;
                    self.copy_match(2, offset, output_size)?;
                }
                269 => {
                    self.in_block = false;
                    return Ok(());
                }
                270..=297 => {
                    let length_slot = symbol - 270;
                    let mut length = LENGTH_BASES[length_slot] + 3;
                    if LENGTH_BITS[length_slot] != 0 {
                        length += self.bits.read_bits(LENGTH_BITS[length_slot])? as usize;
                    }
                    let offset = self.read_offset()?;
                    if offset >= 0x2000 {
                        length += 1;
                    }
                    if offset >= 0x40000 {
                        length += 1;
                    }
                    self.push_old_offset(offset);
                    self.last_offset = offset;
                    self.last_length = length;
                    self.copy_match(length, offset, output_size)?;
                }
                _ => return Err(Error::InvalidData("RAR 2.0 invalid main symbol")),
            }
        }
        Ok(())
    }

    fn read_offset(&mut self) -> Result<usize> {
        let slot = self.offsets.decode(&mut self.bits)?;
        if slot >= OFFSET_COUNT {
            return Err(Error::InvalidData("RAR 2.0 invalid offset slot"));
        }
        let mut offset = OFFSET_BASES[slot] + 1;
        if OFFSET_BITS[slot] != 0 {
            offset += self.bits.read_bits(OFFSET_BITS[slot])? as usize;
        }
        Ok(offset)
    }

    fn copy_match(&mut self, length: usize, offset: usize, output_size: usize) -> Result<()> {
        let offset = if offset == 0 { 1 } else { offset };
        let current = self.current_pos();
        if offset > current {
            return Err(Error::InvalidData("RAR 2.0 match distance is out of range"));
        }
        for index in 0..length {
            if self.current_pos() >= output_size {
                self.pending_match = Some((length - index, offset));
                break;
            }
            let src = self.current_pos() - offset;
            let byte = *self
                .raw_byte(src)
                .ok_or(Error::InvalidData("RAR 2.0 match distance is out of range"))?;
            self.output.push(byte);
        }
        Ok(())
    }

    fn drain_pending_match(&mut self, output_size: usize) -> Result<()> {
        let Some((length, offset)) = self.pending_match.take() else {
            return Ok(());
        };
        self.copy_match(length, offset, output_size)
    }

    fn push_old_offset(&mut self, offset: usize) {
        self.old_offsets[3] = self.old_offsets[2];
        self.old_offsets[2] = self.old_offsets[1];
        self.old_offsets[1] = self.old_offsets[0];
        self.old_offsets[0] = offset;
    }

    fn rotate_old_offset(&mut self, index: usize) {
        let value = self.old_offsets[index];
        for i in (1..=index).rev() {
            self.old_offsets[i] = self.old_offsets[i - 1];
        }
        self.old_offsets[0] = value;
    }

    fn current_pos(&self) -> usize {
        self.base_offset + self.output.len()
    }

    fn raw_byte(&self, position: usize) -> Option<&u8> {
        self.output.get(position.checked_sub(self.base_offset)?)
    }

    fn raw_range(&self, start: usize, end: usize) -> Result<&[u8]> {
        if start < self.base_offset || end < start {
            return Err(Error::InvalidData(
                "RAR 2.0 retained history is unavailable",
            ));
        }
        let rel_start = start - self.base_offset;
        let rel_end = end - self.base_offset;
        self.output
            .get(rel_start..rel_end)
            .ok_or(Error::InvalidData(
                "RAR 2.0 retained history is unavailable",
            ))
    }

    fn trim_history(&mut self, flushed_pos: usize, current_pos: usize) {
        let keep_from = current_pos.saturating_sub(MAX_HISTORY).min(flushed_pos);
        if keep_from <= self.base_offset {
            return;
        }
        let drain = keep_from - self.base_offset;
        self.output.drain(..drain);
        self.base_offset = keep_from;
    }
}

fn fill_levels(levels: &mut [u8], pos: &mut usize, count: usize, value: u8) -> Result<()> {
    let end = pos
        .checked_add(count)
        .ok_or(Error::InvalidData("RAR 2.0 table run overflows"))?;
    let end = end.min(levels.len());
    for item in &mut levels[*pos..end] {
        *item = value;
    }
    *pos = end;
    Ok(())
}

#[derive(Debug, Clone)]
struct Huffman {
    symbols: Vec<HuffmanSymbol>,
}

#[derive(Debug, Clone)]
struct HuffmanSymbol {
    code: u16,
    len: u8,
    symbol: usize,
}

impl Huffman {
    fn empty() -> Self {
        Self {
            symbols: Vec::new(),
        }
    }

    fn from_lengths(lengths: &[u8]) -> Result<Self> {
        let mut count = [0u16; 16];
        for &len in lengths {
            if len > 15 {
                return Err(Error::InvalidData("RAR 2.0 Huffman length is too large"));
            }
            if len != 0 {
                count[len as usize] += 1;
            }
        }
        if count.iter().all(|&value| value == 0) {
            return Ok(Self::empty());
        }

        let mut next_code = [0u16; 16];
        let mut code = 0u16;
        for len in 1..=15 {
            code = (code + count[len - 1]) << 1;
            next_code[len] = code;
        }

        let mut symbols = Vec::new();
        for (symbol, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let code = next_code[len as usize];
            next_code[len as usize] += 1;
            symbols.push(HuffmanSymbol { code, len, symbol });
        }
        symbols.sort_by_key(|item| (item.len, item.code, item.symbol));
        Ok(Self { symbols })
    }

    fn decode(&self, bits: &mut BitReader) -> Result<usize> {
        let mut code = 0u16;
        if self.symbols.is_empty() {
            return Err(Error::InvalidData("RAR 2.0 empty Huffman table"));
        }
        for len in 1..=15 {
            code = (code << 1) | bits.read_bit()? as u16;
            if let Some(item) = self
                .symbols
                .iter()
                .find(|item| item.len == len && item.code == code)
            {
                return Ok(item.symbol);
            }
        }
        Err(Error::InvalidData("RAR 2.0 invalid Huffman code"))
    }
}

#[derive(Debug, Clone)]
struct BitReader {
    input: Vec<u8>,
    bit_pos: usize,
}

impl BitReader {
    fn new() -> Self {
        Self {
            input: Vec::new(),
            bit_pos: 0,
        }
    }

    fn append(&mut self, input: &[u8]) {
        self.compact();
        self.input.extend_from_slice(input);
    }

    fn compact(&mut self) {
        let bytes = self.bit_pos / 8;
        if bytes == 0 {
            return;
        }
        self.input.drain(..bytes);
        self.bit_pos -= bytes * 8;
    }

    fn align_byte(&mut self) {
        self.bit_pos = (self.bit_pos + 7) & !7;
    }

    fn read_bit(&mut self) -> Result<u8> {
        self.read_bits(1).map(|value| value as u8)
    }

    fn read_bits(&mut self, count: u8) -> Result<u32> {
        let value = self.peek_bits(count)?;
        self.bit_pos += count as usize;
        Ok(value)
    }

    fn peek_bits(&self, count: u8) -> Result<u32> {
        if count > 24 {
            return Err(Error::InvalidData("RAR 2.0 bit read is too wide"));
        }
        let mut value = 0u32;
        for i in 0..count as usize {
            let bit_index = self.bit_pos + i;
            let byte = *self.input.get(bit_index / 8).ok_or(Error::NeedMoreInput)?;
            let bit = (byte >> (7 - (bit_index % 8))) & 1;
            value = (value << 1) | bit as u32;
        }
        Ok(value)
    }
}
