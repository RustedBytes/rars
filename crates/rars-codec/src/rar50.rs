use crate::{Error, Result};
use std::ops::Range;

pub const LEVEL_TABLE_SIZE: usize = 20;
pub const MAIN_TABLE_SIZE: usize = 306;
pub const DISTANCE_TABLE_SIZE_50: usize = 64;
pub const DISTANCE_TABLE_SIZE_70: usize = 80;
pub const ALIGN_TABLE_SIZE: usize = 16;
pub const LENGTH_TABLE_SIZE: usize = 44;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedBlock {
    pub header: CompressedBlockHeader,
    pub header_len: usize,
    pub payload: Range<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedBlockHeader {
    pub flags: u8,
    pub is_last: bool,
    pub has_tables: bool,
    pub final_byte_bits: u8,
    pub payload_size: usize,
    pub payload_bits: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableLengths {
    pub main: Vec<u8>,
    pub distance: Vec<u8>,
    pub align: Vec<u8>,
    pub length: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DecodeTables {
    pub main: HuffmanTable,
    pub distance: HuffmanTable,
    pub align: HuffmanTable,
    pub length: HuffmanTable,
    pub align_mode: bool,
}

impl DecodeTables {
    pub fn from_lengths(lengths: &TableLengths) -> Result<Self> {
        let align_mode = lengths
            .align
            .iter()
            .any(|&length| length != 0 && length != 4);
        Ok(Self {
            main: HuffmanTable::from_lengths(&lengths.main)?,
            distance: HuffmanTable::from_lengths(&lengths.distance)?,
            align: HuffmanTable::from_lengths(&lengths.align)?,
            length: HuffmanTable::from_lengths(&lengths.length)?,
            align_mode,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeMode {
    LiteralOnly,
    Lz,
}

pub fn parse_compressed_block(input: &[u8]) -> Result<CompressedBlock> {
    if input.len() < 3 {
        return Err(Error::NeedMoreInput);
    }

    let flags = input[0];
    let checksum = input[1];
    let size_bytes = match (flags >> 3) & 0x03 {
        0 => 1,
        1 => 2,
        2 => 3,
        _ => return Err(Error::InvalidData("RAR 5 block size length is invalid")),
    };
    let header_len = 2 + size_bytes;
    if input.len() < header_len {
        return Err(Error::NeedMoreInput);
    }

    let size_data = &input[2..header_len];
    let actual = size_data
        .iter()
        .fold(checksum ^ flags, |acc, &byte| acc ^ byte);
    if actual != 0x5a {
        return Err(Error::InvalidData("RAR 5 block header checksum mismatch"));
    }

    let payload_size = size_data
        .iter()
        .enumerate()
        .fold(0usize, |acc, (index, &byte)| {
            acc | (usize::from(byte) << (index * 8))
        });
    let payload_end = header_len
        .checked_add(payload_size)
        .ok_or(Error::InvalidData("RAR 5 block size overflows"))?;
    if input.len() < payload_end {
        return Err(Error::NeedMoreInput);
    }

    let final_byte_bits = ((flags & 0x07) + 1).min(8);
    let payload_bits = if payload_size == 0 {
        0
    } else {
        (payload_size - 1) * 8 + usize::from(final_byte_bits)
    };

    Ok(CompressedBlock {
        header: CompressedBlockHeader {
            flags,
            is_last: flags & 0x40 != 0,
            has_tables: flags & 0x80 != 0,
            final_byte_bits,
            payload_size,
            payload_bits,
        },
        header_len,
        payload: header_len..payload_end,
    })
}

pub fn read_level_lengths(input: &[u8]) -> Result<([u8; LEVEL_TABLE_SIZE], usize)> {
    let mut bits = BitReader::new(input);
    let mut lengths = [0; LEVEL_TABLE_SIZE];
    let mut pos = 0;
    while pos < LEVEL_TABLE_SIZE {
        let length = bits.read_bits(4)? as u8;
        if length == 15 {
            let zero_count = bits.read_bits(4)? as usize;
            if zero_count == 0 {
                lengths[pos] = 15;
                pos += 1;
            } else {
                let count = zero_count + 2;
                for _ in 0..count {
                    if pos >= LEVEL_TABLE_SIZE {
                        break;
                    }
                    lengths[pos] = 0;
                    pos += 1;
                }
            }
        } else {
            lengths[pos] = length;
            pos += 1;
        }
    }
    Ok((lengths, bits.bit_pos))
}

pub fn table_length_count(algorithm_version: u8) -> Result<usize> {
    match algorithm_version {
        0 => Ok(MAIN_TABLE_SIZE + DISTANCE_TABLE_SIZE_50 + ALIGN_TABLE_SIZE + LENGTH_TABLE_SIZE),
        1 => Ok(MAIN_TABLE_SIZE + DISTANCE_TABLE_SIZE_70 + ALIGN_TABLE_SIZE + LENGTH_TABLE_SIZE),
        _ => Err(Error::InvalidData(
            "RAR 5 unknown compression algorithm version",
        )),
    }
}

pub fn read_table_lengths(input: &[u8], algorithm_version: u8) -> Result<(TableLengths, usize)> {
    let table_size = table_length_count(algorithm_version)?;
    let (level_lengths, level_bits) = read_level_lengths(input)?;
    let level_decoder = HuffmanTable::from_lengths(&level_lengths)?;
    let mut bits = BitReader::new(input);
    bits.bit_pos = level_bits;

    let mut lengths = Vec::with_capacity(table_size);
    while lengths.len() < table_size {
        let number = level_decoder.decode(&mut bits)?;
        match number {
            0..=15 => lengths.push(number as u8),
            16 | 17 => {
                if lengths.is_empty() {
                    return Err(Error::InvalidData(
                        "RAR 5 table repeats missing previous length",
                    ));
                }
                let count = if number == 16 {
                    3 + bits.read_bits(3)? as usize
                } else {
                    11 + bits.read_bits(7)? as usize
                };
                let previous = *lengths.last().unwrap();
                for _ in 0..count {
                    if lengths.len() >= table_size {
                        break;
                    }
                    lengths.push(previous);
                }
            }
            18 | 19 => {
                let count = if number == 18 {
                    3 + bits.read_bits(3)? as usize
                } else {
                    11 + bits.read_bits(7)? as usize
                };
                for _ in 0..count {
                    if lengths.len() >= table_size {
                        break;
                    }
                    lengths.push(0);
                }
            }
            _ => return Err(Error::InvalidData("RAR 5 invalid level-table symbol")),
        }
    }

    let distance_size = match algorithm_version {
        0 => DISTANCE_TABLE_SIZE_50,
        1 => DISTANCE_TABLE_SIZE_70,
        _ => unreachable!("validated by table_length_count"),
    };
    let distance_start = MAIN_TABLE_SIZE;
    let align_start = distance_start + distance_size;
    let length_start = align_start + ALIGN_TABLE_SIZE;

    Ok((
        TableLengths {
            main: lengths[..distance_start].to_vec(),
            distance: lengths[distance_start..align_start].to_vec(),
            align: lengths[align_start..length_start].to_vec(),
            length: lengths[length_start..].to_vec(),
        },
        bits.bit_pos,
    ))
}

pub fn decode_literal_only(
    input: &[u8],
    algorithm_version: u8,
    output_size: usize,
) -> Result<Vec<u8>> {
    let mut decoder = Unpack50Decoder::new();
    decoder.decode_member(
        input,
        algorithm_version,
        output_size,
        false,
        DecodeMode::LiteralOnly,
    )
}

pub fn decode_lz(input: &[u8], algorithm_version: u8, output_size: usize) -> Result<Vec<u8>> {
    let mut decoder = Unpack50Decoder::new();
    decoder.decode_member(input, algorithm_version, output_size, false, DecodeMode::Lz)
}

#[derive(Debug, Clone)]
pub struct Unpack50Decoder {
    tables: Option<DecodeTables>,
    reps: [usize; 4],
    last_length: usize,
    history: Vec<u8>,
}

impl Unpack50Decoder {
    pub fn new() -> Self {
        Self {
            tables: None,
            reps: [0; 4],
            last_length: 0,
            history: Vec::new(),
        }
    }

    pub fn decode_member(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        output_size: usize,
        solid: bool,
        mode: DecodeMode,
    ) -> Result<Vec<u8>> {
        if !solid {
            self.reset();
        }

        let mut input_pos = 0;
        let mut output = Vec::with_capacity(output_size);
        let mut filters = Vec::new();

        loop {
            let block = parse_compressed_block(&input[input_pos..])?;
            let payload = &input[input_pos + block.payload.start..input_pos + block.payload.end];
            let mut payload_bit_pos = 0;
            if block.header.has_tables {
                let (lengths, table_bits) = read_table_lengths(payload, algorithm_version)?;
                self.tables = Some(DecodeTables::from_lengths(&lengths)?);
                payload_bit_pos = table_bits;
            }
            let tables = self
                .tables
                .as_ref()
                .ok_or(Error::InvalidData("RAR 5 block reuses missing tables"))?
                .clone();
            let mut bits = BitReader::new(payload);
            bits.bit_pos = payload_bit_pos;

            while bits.bit_pos < block.header.payload_bits && output.len() < output_size {
                let symbol = tables.main.decode(&mut bits)?;
                match symbol {
                    0..=255 => output.push(symbol as u8),
                    256 if mode == DecodeMode::Lz => {
                        filters.push(read_filter(&mut bits, output.len())?);
                    }
                    257 if mode == DecodeMode::Lz => {
                        if self.last_length != 0 {
                            self.copy_match(
                                &mut output,
                                self.reps[0],
                                self.last_length,
                                output_size,
                            )?;
                        }
                    }
                    258..=261 if mode == DecodeMode::Lz => {
                        let rep_index = symbol - 258;
                        let distance = self.reps[rep_index];
                        if distance == 0 {
                            return Err(Error::InvalidData(
                                "RAR 5 repeat distance is not initialized",
                            ));
                        }
                        let length_slot = tables.length.decode(&mut bits)?;
                        let length_extra = bits.read_bits(length_slot_extra_bits(length_slot)?)?;
                        let length = slot_to_length(length_slot, length_extra)?;
                        self.reps[..=rep_index].rotate_right(1);
                        self.reps[0] = distance;
                        self.last_length = length;
                        self.copy_match(&mut output, distance, length, output_size)?;
                    }
                    262.. if mode == DecodeMode::Lz => {
                        let length_slot = symbol - 262;
                        let length_extra = bits.read_bits(length_slot_extra_bits(length_slot)?)?;
                        let mut length = slot_to_length(length_slot, length_extra)?;
                        let distance_slot = tables.distance.decode(&mut bits)?;
                        let distance_bit_count = distance_slot_bit_count(distance_slot)?;
                        let distance_extra = if distance_bit_count >= 4 && tables.align_mode {
                            let high = bits.read_bits((distance_bit_count - 4) as u8)?;
                            let low = tables.align.decode(&mut bits)? as u32;
                            (high << 4) | low
                        } else {
                            bits.read_bits(distance_bit_count as u8)?
                        };
                        length += length_bonus(distance_bit_count);
                        let distance = slot_to_distance(distance_slot, distance_extra)?;
                        self.reps.rotate_right(1);
                        self.reps[0] = distance;
                        self.last_length = length;
                        self.copy_match(&mut output, distance, length, output_size)?;
                    }
                    _ if mode == DecodeMode::LiteralOnly => {
                        return Err(Error::InvalidData(
                            "RAR 5 literal-only decoder encountered non-literal symbol",
                        ));
                    }
                    _ => {
                        return Err(Error::InvalidData(
                            "RAR 5 decoder encountered unsupported control symbol",
                        ));
                    }
                }
            }

            input_pos += block.payload.end;
            if block.header.is_last || output.len() >= output_size {
                break;
            }
        }

        if output.len() == output_size {
            apply_filters(&mut output, &filters)?;
            self.history.extend_from_slice(&output);
            Ok(output)
        } else {
            Err(Error::NeedMoreInput)
        }
    }

    fn reset(&mut self) {
        self.tables = None;
        self.reps = [0; 4];
        self.last_length = 0;
        self.history.clear();
    }

    fn copy_match(
        &self,
        output: &mut Vec<u8>,
        distance: usize,
        length: usize,
        output_limit: usize,
    ) -> Result<()> {
        if distance == 0 || distance > self.history.len() + output.len() {
            return Err(Error::InvalidData("RAR 5 match distance exceeds window"));
        }
        if output
            .len()
            .checked_add(length)
            .is_none_or(|end| end > output_limit)
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit"));
        }
        for _ in 0..length {
            if distance <= output.len() {
                let index = output.len() - distance;
                output.push(output[index]);
            } else {
                let history_distance = distance - output.len();
                let index = self.history.len() - history_distance;
                output.push(self.history[index]);
            }
        }
        Ok(())
    }
}

impl Default for Unpack50Decoder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingFilter {
    start: usize,
    length: usize,
    filter_type: FilterType,
    channels: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterType {
    Delta,
    E8,
    E8E9,
    Arm,
}

fn read_filter(bits: &mut BitReader<'_>, current_pos: usize) -> Result<PendingFilter> {
    let offset = read_filter_data(bits)? as usize;
    let length = read_filter_data(bits)? as usize;
    let filter_type = match bits.read_bits(3)? {
        0 => FilterType::Delta,
        1 => FilterType::E8,
        2 => FilterType::E8E9,
        3 => FilterType::Arm,
        _ => return Err(Error::InvalidData("RAR 5 filter type is unsupported")),
    };
    let channels = if filter_type == FilterType::Delta {
        bits.read_bits(5)? as usize + 1
    } else {
        0
    };
    Ok(PendingFilter {
        start: current_pos
            .checked_add(offset)
            .ok_or(Error::InvalidData("RAR 5 filter start overflows"))?,
        length,
        filter_type,
        channels,
    })
}

fn read_filter_data(bits: &mut BitReader<'_>) -> Result<u32> {
    let byte_count = bits.read_bits(2)? as usize + 1;
    let mut data = 0;
    for index in 0..byte_count {
        data |= bits.read_bits(8)? << (index * 8);
    }
    Ok(data)
}

fn apply_filters(output: &mut [u8], filters: &[PendingFilter]) -> Result<()> {
    for filter in filters {
        let end = filter
            .start
            .checked_add(filter.length)
            .ok_or(Error::InvalidData("RAR 5 filter range overflows"))?;
        let data = output
            .get_mut(filter.start..end)
            .ok_or(Error::InvalidData("RAR 5 filter range exceeds output"))?;
        match filter.filter_type {
            FilterType::Delta => {
                let decoded = delta_decode(data, filter.channels)?;
                data.copy_from_slice(&decoded);
            }
            FilterType::E8 => e8e9_decode(data, filter.start as u32, false),
            FilterType::E8E9 => e8e9_decode(data, filter.start as u32, true),
            FilterType::Arm => arm_decode(data, filter.start as u32),
        }
    }
    Ok(())
}

fn e8e9_decode(data: &mut [u8], file_offset: u32, include_e9: bool) {
    if data.len() <= 4 {
        return;
    }
    let cmp_mask = if include_e9 { 0xfe } else { 0xff };
    let mut cur_pos = 0usize;
    while cur_pos < data.len() - 4 {
        cur_pos += 1;
        let opcode = data[cur_pos - 1];
        if opcode & cmp_mask == 0xe8 {
            let offset = file_offset.wrapping_add(cur_pos as u32);
            let addr = u32::from_le_bytes([
                data[cur_pos],
                data[cur_pos + 1],
                data[cur_pos + 2],
                data[cur_pos + 3],
            ]);
            let new_addr = if addr < 0x0100_0000 {
                Some(addr.wrapping_sub(offset))
            } else if addr & 0x8000_0000 != 0 && addr.wrapping_add(offset) & 0x8000_0000 == 0 {
                Some(addr.wrapping_add(0x0100_0000))
            } else {
                None
            };
            if let Some(value) = new_addr {
                data[cur_pos..cur_pos + 4].copy_from_slice(&value.to_le_bytes());
            }
            cur_pos += 4;
        }
    }
}

fn delta_decode(data: &[u8], channels: usize) -> Result<Vec<u8>> {
    if channels == 0 {
        return Err(Error::InvalidData("RAR 5 DELTA filter has zero channels"));
    }
    let mut out = vec![0u8; data.len()];
    let mut src = 0usize;
    for channel in 0..channels {
        let mut prev = 0u8;
        let mut dest = channel;
        while dest < out.len() {
            let byte = *data
                .get(src)
                .ok_or(Error::InvalidData("RAR 5 DELTA filter source is truncated"))?;
            prev = prev.wrapping_sub(byte);
            out[dest] = prev;
            src += 1;
            dest += channels;
        }
    }
    Ok(out)
}

fn arm_decode(data: &mut [u8], file_offset: u32) {
    let mut pos = 0usize;
    while pos + 3 < data.len() {
        if data[pos + 3] == 0xeb {
            let mut offset = u32::from(data[pos])
                | (u32::from(data[pos + 1]) << 8)
                | (u32::from(data[pos + 2]) << 16);
            offset = offset.wrapping_sub((file_offset + pos as u32) / 4);
            data[pos] = offset as u8;
            data[pos + 1] = (offset >> 8) as u8;
            data[pos + 2] = (offset >> 16) as u8;
        }
        pos += 4;
    }
}

fn length_slot_extra_bits(slot: usize) -> Result<u8> {
    if slot < 8 {
        Ok(0)
    } else {
        let bit_count = (slot >> 2) - 1;
        if bit_count > 24 {
            Err(Error::InvalidData("RAR 5 length slot is too large"))
        } else {
            Ok(bit_count as u8)
        }
    }
}

fn length_bonus(distance_bit_count: usize) -> usize {
    match distance_bit_count {
        0..=6 => 0,
        7..=11 => 1,
        12..=16 => 2,
        _ => 3,
    }
}

pub fn slot_to_length(slot: usize, extra_bits: u32) -> Result<usize> {
    if slot < 8 {
        return Ok(slot + 2);
    }
    let bit_count = (slot >> 2) - 1;
    if bit_count > 24 {
        return Err(Error::InvalidData("RAR 5 length slot is too large"));
    }
    let max_extra = if bit_count == 32 {
        u32::MAX
    } else {
        (1u32 << bit_count) - 1
    };
    if extra_bits > max_extra {
        return Err(Error::InvalidData("RAR 5 length extra bits exceed slot"));
    }
    Ok((((4 | (slot & 3)) << bit_count) | extra_bits as usize) + 2)
}

pub fn distance_slot_bit_count(slot: usize) -> Result<usize> {
    if slot < 4 {
        Ok(0)
    } else {
        let bit_count = (slot - 2) >> 1;
        if bit_count > 31 {
            Err(Error::InvalidData("RAR 5 distance slot is too large"))
        } else {
            Ok(bit_count)
        }
    }
}

pub fn slot_to_distance(slot: usize, extra_bits: u32) -> Result<usize> {
    if slot < 4 {
        return Ok(slot + 1);
    }
    let bit_count = distance_slot_bit_count(slot)?;
    let max_extra = if bit_count == 32 {
        u32::MAX
    } else {
        (1u32 << bit_count) - 1
    };
    if extra_bits > max_extra {
        return Err(Error::InvalidData("RAR 5 distance extra bits exceed slot"));
    }
    Ok((((2 | (slot & 1)) << bit_count) | extra_bits as usize) + 1)
}

#[derive(Debug, Clone)]
pub struct HuffmanTable {
    symbols: Vec<HuffmanSymbol>,
}

#[derive(Debug, Clone)]
struct HuffmanSymbol {
    code: u16,
    len: u8,
    symbol: usize,
}

impl HuffmanTable {
    pub fn from_lengths(lengths: &[u8]) -> Result<Self> {
        let mut count = [0u16; 16];
        for &length in lengths {
            if length > 15 {
                return Err(Error::InvalidData("RAR 5 Huffman length is too large"));
            }
            if length != 0 {
                count[length as usize] += 1;
            }
        }

        let mut next_code = [0u16; 16];
        let mut code = 0u16;
        for length in 1..=15 {
            code = (code + count[length - 1]) << 1;
            next_code[length] = code;
        }

        let mut symbols = Vec::new();
        for (symbol, &length) in lengths.iter().enumerate() {
            if length == 0 {
                continue;
            }
            let code = next_code[length as usize];
            next_code[length as usize] += 1;
            symbols.push(HuffmanSymbol {
                code,
                len: length,
                symbol,
            });
        }
        symbols.sort_by_key(|item| (item.len, item.code, item.symbol));
        Ok(Self { symbols })
    }

    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    fn decode(&self, bits: &mut BitReader<'_>) -> Result<usize> {
        if self.symbols.is_empty() {
            return Err(Error::InvalidData("RAR 5 empty Huffman table"));
        }
        let mut code = 0u16;
        for len in 1..=15 {
            code = (code << 1) | bits.read_bits(1)? as u16;
            if let Some(symbol) = self
                .symbols
                .iter()
                .find(|symbol| symbol.len == len && symbol.code == code)
            {
                return Ok(symbol.symbol);
            }
        }
        Err(Error::InvalidData("RAR 5 invalid Huffman code"))
    }
}

struct BitReader<'a> {
    input: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, bit_pos: 0 }
    }

    fn read_bits(&mut self, count: u8) -> Result<u32> {
        if count > 24 {
            return Err(Error::InvalidData("RAR 5 bit read is too wide"));
        }
        let mut value = 0;
        for _ in 0..count {
            let byte = *self
                .input
                .get(self.bit_pos / 8)
                .ok_or(Error::NeedMoreInput)?;
            let bit = (byte >> (7 - (self.bit_pos % 8))) & 1;
            value = (value << 1) | u32::from(bit);
            self.bit_pos += 1;
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checksum(flags: u8, size_bytes: &[u8]) -> u8 {
        size_bytes
            .iter()
            .fold(0x5a ^ flags, |acc, &byte| acc ^ byte)
    }

    #[test]
    fn parses_one_byte_size_block_header() {
        let flags = 0xc7;
        let size = [3];
        let input = [flags, checksum(flags, &size), size[0], 0xaa, 0xbb, 0xcc];

        let block = parse_compressed_block(&input).unwrap();
        assert_eq!(block.header_len, 3);
        assert_eq!(block.payload, 3..6);
        assert_eq!(block.header.flags, flags);
        assert!(block.header.is_last);
        assert!(block.header.has_tables);
        assert_eq!(block.header.final_byte_bits, 8);
        assert_eq!(block.header.payload_size, 3);
        assert_eq!(block.header.payload_bits, 24);
    }

    #[test]
    fn parses_three_byte_size_block_header_with_partial_final_byte() {
        let flags = 0x94;
        let size = [0x34, 0x12, 0x00];
        let mut input = vec![flags, checksum(flags, &size), size[0], size[1], size[2]];
        input.resize(0x1234 + 5, 0);

        let block = parse_compressed_block(&input).unwrap();
        assert_eq!(block.header_len, 5);
        assert_eq!(block.payload, 5..0x1239);
        assert!(!block.header.is_last);
        assert!(block.header.has_tables);
        assert_eq!(block.header.final_byte_bits, 5);
        assert_eq!(block.header.payload_size, 0x1234);
        assert_eq!(block.header.payload_bits, (0x1234 - 1) * 8 + 5);
    }

    #[test]
    fn rejects_reserved_size_length_selector() {
        let input = [0x18, 0x42, 0x00];

        assert_eq!(
            parse_compressed_block(&input),
            Err(Error::InvalidData("RAR 5 block size length is invalid"))
        );
    }

    #[test]
    fn rejects_bad_block_header_checksum() {
        let input = [0xc7, 0x00, 0x03, 0xaa, 0xbb, 0xcc];

        assert_eq!(
            parse_compressed_block(&input),
            Err(Error::InvalidData("RAR 5 block header checksum mismatch"))
        );
    }

    #[test]
    fn rejects_truncated_block_payload() {
        let flags = 0xc7;
        let size = [3];
        let input = [flags, checksum(flags, &size), size[0], 0xaa, 0xbb];

        assert_eq!(parse_compressed_block(&input), Err(Error::NeedMoreInput));
    }

    #[test]
    fn reads_level_lengths_with_literal_fifteen() {
        let mut nibbles = vec![1, 2, 15, 0, 3, 4];
        nibbles.resize(LEVEL_TABLE_SIZE + 1, 0);

        let (lengths, bits) = read_level_lengths(&pack_nibbles(&nibbles)).unwrap();

        assert_eq!(&lengths[..6], &[1, 2, 15, 3, 4, 0]);
        assert_eq!(bits, LEVEL_TABLE_SIZE * 4 + 4);
    }

    #[test]
    fn reads_level_lengths_with_zero_run_at_current_position() {
        let mut nibbles = vec![7, 15, 3, 2];
        nibbles.resize(LEVEL_TABLE_SIZE - 3, 0);

        let (lengths, bits) = read_level_lengths(&pack_nibbles(&nibbles)).unwrap();

        assert_eq!(lengths[0], 7);
        assert_eq!(&lengths[1..6], &[0, 0, 0, 0, 0]);
        assert_eq!(lengths[6], 2);
        assert_eq!(bits, (LEVEL_TABLE_SIZE - 3) * 4);
    }

    fn pack_nibbles(nibbles: &[u8]) -> Vec<u8> {
        nibbles
            .chunks(2)
            .map(|chunk| {
                let high = chunk[0] & 0x0f;
                let low = chunk.get(1).copied().unwrap_or(0) & 0x0f;
                (high << 4) | low
            })
            .collect()
    }

    #[test]
    fn reads_rar50_second_level_table_lengths() {
        let mut writer = BitWriter::new();
        for _ in 0..LEVEL_TABLE_SIZE {
            writer.write_bits(5, 4);
        }
        for count in [138, 138, 138, 16] {
            writer.write_bits(19, 5);
            writer.write_bits(count - 11, 7);
        }
        let input = writer.finish();

        let (lengths, bits) = read_table_lengths(&input, 0).unwrap();

        assert_eq!(lengths.main.len(), MAIN_TABLE_SIZE);
        assert_eq!(lengths.distance.len(), DISTANCE_TABLE_SIZE_50);
        assert_eq!(lengths.align.len(), ALIGN_TABLE_SIZE);
        assert_eq!(lengths.length.len(), LENGTH_TABLE_SIZE);
        assert!(lengths.main.iter().all(|&length| length == 0));
        assert!(lengths.distance.iter().all(|&length| length == 0));
        assert!(lengths.align.iter().all(|&length| length == 0));
        assert!(lengths.length.iter().all(|&length| length == 0));
        assert_eq!(bits, LEVEL_TABLE_SIZE * 4 + 4 * (5 + 7));
    }

    #[test]
    fn reads_rar70_table_length_count() {
        assert_eq!(
            table_length_count(1).unwrap(),
            MAIN_TABLE_SIZE + DISTANCE_TABLE_SIZE_70 + ALIGN_TABLE_SIZE + LENGTH_TABLE_SIZE
        );
    }

    #[test]
    fn rejects_table_repeat_without_previous_length() {
        let mut writer = BitWriter::new();
        for _ in 0..LEVEL_TABLE_SIZE {
            writer.write_bits(5, 4);
        }
        writer.write_bits(16, 5);
        writer.write_bits(0, 3);

        assert_eq!(
            read_table_lengths(&writer.finish(), 0),
            Err(Error::InvalidData(
                "RAR 5 table repeats missing previous length"
            ))
        );
    }

    #[test]
    fn builds_named_decode_tables_from_lengths() {
        let lengths = TableLengths {
            main: vec![1, 1],
            distance: vec![1, 1],
            align: vec![4; ALIGN_TABLE_SIZE],
            length: vec![1, 1],
        };

        let tables = DecodeTables::from_lengths(&lengths).unwrap();

        assert!(!tables.main.is_empty());
        assert!(!tables.distance.is_empty());
        assert!(!tables.align.is_empty());
        assert!(!tables.length.is_empty());
        assert!(!tables.align_mode);
    }

    #[test]
    fn detects_rar50_align_mode_when_align_lengths_are_not_uniform_four() {
        let mut align = vec![4; ALIGN_TABLE_SIZE];
        align[3] = 3;
        let lengths = TableLengths {
            main: vec![1, 1],
            distance: vec![1, 1],
            align,
            length: vec![1, 1],
        };

        let tables = DecodeTables::from_lengths(&lengths).unwrap();

        assert!(tables.align_mode);
    }

    #[test]
    fn decodes_synthetic_literal_only_block() {
        let payload = literal_only_payload(b"ABBA");
        let input = compressed_block(0xc7, &payload);

        let output = decode_literal_only(&input, 0, 4).unwrap();

        assert_eq!(output, b"ABBA");
    }

    #[test]
    fn decodes_synthetic_new_match_block() {
        let payload = new_match_payload();
        let input = compressed_block(0xc7, &payload);

        let output = decode_lz(&input, 0, 4).unwrap();

        assert_eq!(output, b"ABAB");
    }

    #[test]
    fn decodes_synthetic_last_length_match_block() {
        let payload = repeat_payload(257);
        let input = compressed_block(0xc7, &payload);

        let output = decode_lz(&input, 0, 6).unwrap();

        assert_eq!(output, b"ABABAB");
    }

    #[test]
    fn decodes_synthetic_repeat_distance_match_block() {
        let payload = repeat_payload(258);
        let input = compressed_block(0xc7, &payload);

        let output = decode_lz(&input, 0, 6).unwrap();

        assert_eq!(output, b"ABABAB");
    }

    #[test]
    fn rejects_literal_only_block_without_tables() {
        let input = compressed_block(0x47, &[0]);

        assert_eq!(
            decode_literal_only(&input, 0, 1),
            Err(Error::InvalidData("RAR 5 block reuses missing tables"))
        );
    }

    #[test]
    fn decodes_length_slots() {
        assert_eq!(slot_to_length(0, 0).unwrap(), 2);
        assert_eq!(slot_to_length(7, 0).unwrap(), 9);
        assert_eq!(slot_to_length(8, 0).unwrap(), 10);
        assert_eq!(slot_to_length(8, 1).unwrap(), 11);
        assert_eq!(slot_to_length(11, 1).unwrap(), 17);
        assert_eq!(slot_to_length(12, 3).unwrap(), 21);
    }

    #[test]
    fn decodes_distance_slots() {
        assert_eq!(slot_to_distance(0, 0).unwrap(), 1);
        assert_eq!(slot_to_distance(3, 0).unwrap(), 4);
        assert_eq!(distance_slot_bit_count(4).unwrap(), 1);
        assert_eq!(slot_to_distance(4, 0).unwrap(), 5);
        assert_eq!(slot_to_distance(4, 1).unwrap(), 6);
        assert_eq!(distance_slot_bit_count(10).unwrap(), 4);
        assert_eq!(slot_to_distance(10, 15).unwrap(), 48);
    }

    #[test]
    fn copies_lz_matches_with_overlap() {
        let decoder = Unpack50Decoder::new();
        let mut output = b"AB".to_vec();

        decoder.copy_match(&mut output, 2, 6, 8).unwrap();

        assert_eq!(output, b"ABABABAB");
    }

    #[test]
    fn rejects_invalid_match_copy() {
        let decoder = Unpack50Decoder::new();
        let mut output = b"AB".to_vec();

        assert_eq!(
            decoder.copy_match(&mut output, 3, 1, 3),
            Err(Error::InvalidData("RAR 5 match distance exceeds window"))
        );
        assert_eq!(
            decoder.copy_match(&mut output, 1, 2, 3),
            Err(Error::InvalidData("RAR 5 match exceeds output limit"))
        );
    }

    struct BitWriter {
        bytes: Vec<u8>,
        bit_pos: usize,
    }

    impl BitWriter {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                bit_pos: 0,
            }
        }

        fn write_bits(&mut self, value: usize, count: usize) {
            for bit in (0..count).rev() {
                if self.bit_pos.is_multiple_of(8) {
                    self.bytes.push(0);
                }
                if (value >> bit) & 1 != 0 {
                    let byte = self.bytes.last_mut().unwrap();
                    *byte |= 1 << (7 - (self.bit_pos % 8));
                }
                self.bit_pos += 1;
            }
        }

        fn finish(self) -> Vec<u8> {
            self.bytes
        }
    }

    fn compressed_block(flags: u8, payload: &[u8]) -> Vec<u8> {
        assert!(payload.len() <= 0xff);
        let size = [payload.len() as u8];
        let mut block = vec![flags, checksum(flags, &size), size[0]];
        block.extend_from_slice(payload);
        block
    }

    fn literal_only_payload(data: &[u8]) -> Vec<u8> {
        let mut writer = BitWriter::new();
        for _ in 0..LEVEL_TABLE_SIZE {
            writer.write_bits(5, 4);
        }
        write_zero_lengths(&mut writer, b'A' as usize);
        writer.write_bits(1, 5);
        writer.write_bits(1, 5);
        write_zero_lengths(
            &mut writer,
            table_length_count(0).unwrap() - b'A' as usize - 2,
        );
        for &byte in data {
            match byte {
                b'A' => writer.write_bits(0, 1),
                b'B' => writer.write_bits(1, 1),
                _ => panic!("test helper only encodes A/B"),
            }
        }
        writer.finish()
    }

    fn new_match_payload() -> Vec<u8> {
        let mut writer = BitWriter::new();
        for _ in 0..LEVEL_TABLE_SIZE {
            writer.write_bits(5, 4);
        }
        write_zero_lengths(&mut writer, b'A' as usize);
        writer.write_bits(2, 5); // main literal 'A'
        writer.write_bits(2, 5); // main literal 'B'
        write_zero_lengths(&mut writer, 262 - b'B' as usize - 1);
        writer.write_bits(2, 5); // main new-match symbol 262, length slot 0
        write_zero_lengths(&mut writer, MAIN_TABLE_SIZE - 263);
        writer.write_bits(0, 5); // distance slot 0 unused
        writer.write_bits(1, 5); // distance slot 1, distance 2
        write_zero_lengths(&mut writer, DISTANCE_TABLE_SIZE_50 - 2);
        write_zero_lengths(&mut writer, ALIGN_TABLE_SIZE);
        write_zero_lengths(&mut writer, LENGTH_TABLE_SIZE);

        writer.write_bits(0b00, 2); // 'A'
        writer.write_bits(0b01, 2); // 'B'
        writer.write_bits(0b10, 2); // match length 2
        writer.write_bits(0, 1); // distance slot 1
        writer.finish()
    }

    fn repeat_payload(repeat_symbol: usize) -> Vec<u8> {
        let mut writer = BitWriter::new();
        for _ in 0..LEVEL_TABLE_SIZE {
            writer.write_bits(5, 4);
        }
        write_zero_lengths(&mut writer, b'A' as usize);
        writer.write_bits(2, 5); // main literal 'A'
        writer.write_bits(2, 5); // main literal 'B'
        write_zero_lengths(&mut writer, repeat_symbol - b'B' as usize - 1);
        writer.write_bits(2, 5); // repeat control symbol
        write_zero_lengths(&mut writer, 262 - repeat_symbol - 1);
        writer.write_bits(2, 5); // main new-match symbol 262, length slot 0
        write_zero_lengths(&mut writer, MAIN_TABLE_SIZE - 263);
        writer.write_bits(0, 5); // distance slot 0 unused
        writer.write_bits(1, 5); // distance slot 1, distance 2
        write_zero_lengths(&mut writer, DISTANCE_TABLE_SIZE_50 - 2);
        write_zero_lengths(&mut writer, ALIGN_TABLE_SIZE);
        writer.write_bits(1, 5); // length table slot 0, length 2
        write_zero_lengths(&mut writer, LENGTH_TABLE_SIZE - 1);

        writer.write_bits(0b00, 2); // 'A'
        writer.write_bits(0b01, 2); // 'B'
        writer.write_bits(0b11, 2); // match length 2
        writer.write_bits(0, 1); // distance slot 1
        writer.write_bits(0b10, 2); // repeat control symbol
        if repeat_symbol == 258 {
            writer.write_bits(0, 1); // length slot 0
        }
        writer.finish()
    }

    fn write_zero_lengths(writer: &mut BitWriter, mut count: usize) {
        while count >= 11 {
            let run = count.min(138);
            writer.write_bits(19, 5);
            writer.write_bits(run - 11, 7);
            count -= run;
        }
        while count >= 3 {
            let run = count.min(10);
            writer.write_bits(18, 5);
            writer.write_bits(run - 3, 3);
            count -= run;
        }
        for _ in 0..count {
            writer.write_bits(0, 5);
        }
    }
}
