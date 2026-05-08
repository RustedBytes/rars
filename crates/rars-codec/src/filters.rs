use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterOp {
    E8,
    E8E9,
    Delta { channels: usize },
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DeltaErrorMessages {
    pub invalid_channels: &'static str,
    pub zero_channels: &'static str,
    pub truncated_source: &'static str,
}

#[cfg(test)]
pub(crate) fn encode(op: FilterOp, data: &[u8], file_offset: u32) -> Result<Vec<u8>> {
    encode_with_messages(op, data, file_offset, DeltaErrorMessages::generic())
}

#[cfg(test)]
pub(crate) fn encode_with_messages(
    op: FilterOp,
    data: &[u8],
    file_offset: u32,
    messages: DeltaErrorMessages,
) -> Result<Vec<u8>> {
    match op {
        FilterOp::E8 => {
            let mut out = data.to_vec();
            e8e9_encode(&mut out, file_offset, false);
            Ok(out)
        }
        FilterOp::E8E9 => {
            let mut out = data.to_vec();
            e8e9_encode(&mut out, file_offset, true);
            Ok(out)
        }
        FilterOp::Delta { channels } => delta_encode(data, channels, messages),
    }
}

pub(crate) fn encode_in_place(
    op: FilterOp,
    data: &mut [u8],
    file_offset: u32,
    messages: DeltaErrorMessages,
) -> Result<()> {
    match op {
        FilterOp::E8 => e8e9_encode(data, file_offset, false),
        FilterOp::E8E9 => e8e9_encode(data, file_offset, true),
        FilterOp::Delta { channels } => {
            let encoded = delta_encode(data, channels, messages)?;
            data.copy_from_slice(&encoded);
        }
    }
    Ok(())
}

pub(crate) fn decode_in_place(
    op: FilterOp,
    data: &mut Vec<u8>,
    file_offset: u32,
    messages: DeltaErrorMessages,
) -> Result<()> {
    match op {
        FilterOp::E8 => e8e9_decode(data, file_offset, false),
        FilterOp::E8E9 => e8e9_decode(data, file_offset, true),
        FilterOp::Delta { channels } => {
            *data = delta_decode(data, channels, messages)?;
        }
    }
    Ok(())
}

pub(crate) fn e8e9_decode(data: &mut [u8], file_offset: u32, include_e9: bool) {
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

pub(crate) fn e8e9_encode(data: &mut [u8], file_offset: u32, include_e9: bool) {
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
            let candidate = addr.wrapping_add(offset);
            if candidate < 0x0100_0000 {
                data[cur_pos..cur_pos + 4].copy_from_slice(&candidate.to_le_bytes());
            } else {
                let candidate = addr.wrapping_sub(0x0100_0000);
                if candidate & 0x8000_0000 != 0 && candidate.wrapping_add(offset) & 0x8000_0000 == 0
                {
                    data[cur_pos..cur_pos + 4].copy_from_slice(&candidate.to_le_bytes());
                }
            }
            cur_pos += 4;
        }
    }
}

pub(crate) fn delta_decode(
    data: &[u8],
    channels: usize,
    messages: DeltaErrorMessages,
) -> Result<Vec<u8>> {
    if channels == 0 {
        return Err(Error::InvalidData(messages.zero_channels));
    }
    if channels > 32 {
        return Err(Error::InvalidData(messages.invalid_channels));
    }
    let mut out = vec![0u8; data.len()];
    let mut src = 0usize;
    for channel in 0..channels {
        let mut prev = 0u8;
        let mut dest = channel;
        while dest < out.len() {
            let byte = *data
                .get(src)
                .ok_or(Error::InvalidData(messages.truncated_source))?;
            prev = prev.wrapping_sub(byte);
            out[dest] = prev;
            src += 1;
            dest += channels;
        }
    }
    Ok(out)
}

pub(crate) fn delta_encode(
    data: &[u8],
    channels: usize,
    messages: DeltaErrorMessages,
) -> Result<Vec<u8>> {
    if channels == 0 || channels > 32 {
        return Err(Error::InvalidData(messages.invalid_channels));
    }
    let mut out = Vec::with_capacity(data.len());
    for channel in 0..channels {
        let mut prev = 0u8;
        let mut src = channel;
        while src < data.len() {
            let byte = data[src];
            out.push(prev.wrapping_sub(byte));
            prev = byte;
            src += channels;
        }
    }
    Ok(out)
}

impl DeltaErrorMessages {
    #[cfg(test)]
    pub(crate) const fn generic() -> Self {
        Self {
            invalid_channels: "DELTA filter channel count is invalid",
            zero_channels: "DELTA filter has zero channels",
            truncated_source: "DELTA filter source is truncated",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn x86_sample() -> Vec<u8> {
        let mut data = b"prefix ".to_vec();
        data.extend_from_slice(&[0xe8, 0x10, 0x20, 0x00, 0x00]);
        data.extend_from_slice(b" middle ");
        data.extend_from_slice(&[0xe9, 0xf0, 0xff, 0xff, 0xff]);
        data.extend_from_slice(b" suffix");
        data
    }

    #[test]
    fn e8_transform_round_trips_representative_bytes() {
        let input = x86_sample();
        let mut filtered = encode(FilterOp::E8, &input, 4096).unwrap();

        decode_in_place(
            FilterOp::E8,
            &mut filtered,
            4096,
            DeltaErrorMessages::generic(),
        )
        .unwrap();

        assert_eq!(filtered, input);
    }

    #[test]
    fn e8e9_transform_round_trips_representative_bytes() {
        let input = x86_sample();
        let mut filtered = encode(FilterOp::E8E9, &input, 8192).unwrap();

        decode_in_place(
            FilterOp::E8E9,
            &mut filtered,
            8192,
            DeltaErrorMessages::generic(),
        )
        .unwrap();

        assert_eq!(filtered, input);
    }

    #[test]
    fn delta_transform_round_trips_interleaved_channels() {
        let input = b"abcdefghijklmnopqrstuvwxyz0123456789".repeat(3);
        let mut filtered = encode(FilterOp::Delta { channels: 3 }, &input, 0).unwrap();

        decode_in_place(
            FilterOp::Delta { channels: 3 },
            &mut filtered,
            0,
            DeltaErrorMessages::generic(),
        )
        .unwrap();

        assert_eq!(filtered, input);
    }

    #[test]
    fn delta_decode_rejects_channel_counts_above_writer_limit() {
        let mut filtered = vec![0; 64];

        assert_eq!(
            decode_in_place(
                FilterOp::Delta { channels: 33 },
                &mut filtered,
                0,
                DeltaErrorMessages::generic(),
            ),
            Err(Error::InvalidData("DELTA filter channel count is invalid"))
        );
    }

    #[test]
    fn encode_in_place_matches_allocating_encode() {
        let input = x86_sample();
        let expected = encode(FilterOp::E8E9, &input, 1234).unwrap();
        let mut actual = input;

        encode_in_place(
            FilterOp::E8E9,
            &mut actual,
            1234,
            DeltaErrorMessages::generic(),
        )
        .unwrap();

        assert_eq!(actual, expected);
    }
}
