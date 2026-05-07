//! Recovery-record primitives shared by RAR writer and repair code.
//!
//! RAR 5 recovery data uses GF(2^16) with reduction polynomial `0x1100b`
//! and a Cauchy encoder matrix. This crate intentionally exposes the field
//! and matrix building blocks before wiring them into archive serialization.

pub mod rar3 {
    const MAX_PARITY: usize = 255;
    const MAX_POLYNOMIAL: usize = 512;
    const PRIMITIVE_POLYNOMIAL: u16 = 0x11d;

    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum Error {
        InvalidParitySize,
        InvalidCodewordSize,
        TooManyErasures,
        DecodeFailed,
    }

    pub type Result<T> = std::result::Result<T, Error>;

    #[derive(Debug, Clone)]
    pub(crate) struct RSCoder8 {
        parity_size: usize,
        gf_exp: [u8; MAX_POLYNOMIAL],
        gf_log: [u16; MAX_PARITY + 1],
        generator: Vec<u8>,
    }

    impl RSCoder8 {
        pub(crate) fn new(parity_size: usize) -> Result<Self> {
            if parity_size == 0 || parity_size > MAX_PARITY {
                return Err(Error::InvalidParitySize);
            }
            let mut coder = Self {
                parity_size,
                gf_exp: [0; MAX_POLYNOMIAL],
                gf_log: [0; MAX_PARITY + 1],
                generator: vec![0; parity_size],
            };
            coder.init_field();
            coder.init_generator();
            Ok(coder)
        }

        #[cfg(test)]
        fn encode(&self, data: &[u8]) -> Vec<u8> {
            let mut shift = vec![0u8; self.parity_size + 1];
            for &byte in data {
                let feedback = byte ^ shift[self.parity_size - 1];
                for index in (1..self.parity_size).rev() {
                    shift[index] = shift[index - 1] ^ self.mul(self.generator[index], feedback);
                }
                shift[0] = self.mul(self.generator[0], feedback);
            }
            (0..self.parity_size)
                .map(|index| shift[self.parity_size - index - 1])
                .collect()
        }

        pub(crate) fn correct_erasures(
            &self,
            codeword: &mut [u8],
            erasures: &[usize],
        ) -> Result<()> {
            if codeword.is_empty() || codeword.len() > MAX_PARITY {
                return Err(Error::InvalidCodewordSize);
            }
            if erasures.len() > self.parity_size {
                return Err(Error::TooManyErasures);
            }
            if erasures.iter().any(|&index| index >= codeword.len()) {
                return Err(Error::InvalidCodewordSize);
            }

            let mut syndromes = vec![0u8; self.parity_size];
            let mut all_zero = true;
            for (index, syndrome) in syndromes.iter_mut().enumerate() {
                let factor = self.gf_exp[index + 1];
                let mut sum = 0;
                for &byte in codeword.iter() {
                    sum = byte ^ self.mul(factor, sum);
                }
                *syndrome = sum;
                all_zero &= sum == 0;
            }
            if all_zero {
                return Ok(());
            }
            if erasures.is_empty() {
                return Err(Error::DecodeFailed);
            }

            let mut locator = vec![0u8; self.parity_size + 1];
            locator[0] = 1;
            for &erasure in erasures {
                let multiplier = self.gf_exp[codeword.len() - erasure - 1];
                for index in (1..=self.parity_size).rev() {
                    locator[index] ^= self.mul(multiplier, locator[index - 1]);
                }
            }

            let mut error_locs = Vec::new();
            let mut denominators = Vec::new();
            for root in (MAX_PARITY - codeword.len())..=MAX_PARITY {
                let mut sum = 0;
                for (power, &coefficient) in locator.iter().enumerate() {
                    sum ^= self.mul(self.gf_exp[(power * root) % MAX_PARITY], coefficient);
                }
                if sum == 0 {
                    let loc = MAX_PARITY - root;
                    error_locs.push(loc);
                    let mut denominator = 0;
                    for index in (1..=self.parity_size).step_by(2) {
                        denominator ^= self.mul(
                            locator[index],
                            self.gf_exp[(root * (index - 1)) % MAX_PARITY],
                        );
                    }
                    denominators.push(denominator);
                }
            }
            if error_locs.is_empty() || error_locs.len() > self.parity_size {
                return Err(Error::DecodeFailed);
            }

            let evaluator = self.multiply_polynomials(&locator, &syndromes);
            for (&loc, &denominator) in error_locs.iter().zip(&denominators) {
                if denominator == 0 {
                    return Err(Error::DecodeFailed);
                }
                let data_pos = codeword
                    .len()
                    .checked_sub(loc + 1)
                    .ok_or(Error::DecodeFailed)?;
                let dloc = MAX_PARITY - loc;
                let mut numerator = 0;
                for (index, &coefficient) in evaluator.iter().enumerate() {
                    numerator ^= self.mul(coefficient, self.gf_exp[(dloc * index) % MAX_PARITY]);
                }
                let correction = self.mul(
                    numerator,
                    self.gf_exp[MAX_PARITY - usize::from(self.gf_log[denominator as usize])],
                );
                codeword[data_pos] ^= correction;
            }
            Ok(())
        }

        fn init_field(&mut self) {
            let mut value = 1u16;
            for index in 0..MAX_PARITY {
                self.gf_log[value as usize] = index as u16;
                self.gf_exp[index] = value as u8;
                value <<= 1;
                if value > 0xff {
                    value ^= PRIMITIVE_POLYNOMIAL;
                }
            }
            for index in MAX_PARITY..MAX_POLYNOMIAL {
                self.gf_exp[index] = self.gf_exp[index - MAX_PARITY];
            }
        }

        fn init_generator(&mut self) {
            let mut current = vec![0u8; self.parity_size];
            current[0] = 1;
            for index in 1..=self.parity_size {
                let mut factor = vec![0u8; self.parity_size];
                factor[0] = self.gf_exp[index];
                if self.parity_size > 1 {
                    factor[1] = 1;
                }
                self.generator = self.multiply_polynomials(&factor, &current);
                current.clone_from(&self.generator);
            }
        }

        fn multiply_polynomials(&self, left: &[u8], right: &[u8]) -> Vec<u8> {
            let mut out = vec![0u8; self.parity_size];
            for left_index in 0..self.parity_size {
                if left.get(left_index).copied().unwrap_or(0) == 0 {
                    continue;
                }
                for right_index in 0..(self.parity_size - left_index) {
                    out[left_index + right_index] ^= self.mul(
                        left[left_index],
                        right.get(right_index).copied().unwrap_or(0),
                    );
                }
            }
            out
        }

        fn mul(&self, left: u8, right: u8) -> u8 {
            if left == 0 || right == 0 {
                0
            } else {
                self.gf_exp[usize::from(self.gf_log[left as usize] + self.gf_log[right as usize])]
            }
        }
    }

    pub fn reconstruct_data_volumes(
        data_volumes: &[Option<&[u8]>],
        recovery_count: usize,
        recovery_volumes: &[(usize, &[u8])],
    ) -> Result<Vec<Vec<u8>>> {
        if data_volumes.is_empty() || data_volumes.len() + recovery_count > MAX_PARITY {
            return Err(Error::InvalidCodewordSize);
        }
        if recovery_volumes.is_empty() || recovery_count == 0 || recovery_count > MAX_PARITY {
            return Err(Error::InvalidParitySize);
        }
        let shard_len = recovery_volumes[0].1.len();
        if recovery_volumes
            .iter()
            .any(|&(index, data)| index >= recovery_count || data.len() != shard_len)
        {
            return Err(Error::InvalidCodewordSize);
        }
        if data_volumes
            .iter()
            .flatten()
            .any(|data| data.len() > shard_len)
        {
            return Err(Error::InvalidCodewordSize);
        }

        let mut recovery_by_index = vec![None; recovery_count];
        for &(index, data) in recovery_volumes {
            if recovery_by_index[index].replace(data).is_some() {
                return Err(Error::InvalidCodewordSize);
            }
        }

        let missing_data: Vec<_> = data_volumes
            .iter()
            .enumerate()
            .filter_map(|(index, data)| data.is_none().then_some(index))
            .collect();
        if missing_data.is_empty() {
            return Ok(data_volumes
                .iter()
                .map(|data| {
                    let mut out = vec![0; shard_len];
                    if let Some(data) = data {
                        out[..data.len()].copy_from_slice(data);
                    }
                    out
                })
                .collect());
        }

        let missing_recovery: Vec<_> = recovery_by_index
            .iter()
            .enumerate()
            .filter_map(|(index, data)| data.is_none().then_some(data_volumes.len() + index))
            .collect();
        let mut erasures = missing_data.clone();
        erasures.extend(missing_recovery);
        if erasures.len() > recovery_count {
            return Err(Error::TooManyErasures);
        }

        let coder = RSCoder8::new(recovery_count)?;
        let mut out: Vec<Vec<u8>> = data_volumes
            .iter()
            .map(|data| {
                let mut shard = vec![0; shard_len];
                if let Some(data) = data {
                    shard[..data.len()].copy_from_slice(data);
                }
                shard
            })
            .collect();

        for offset in 0..shard_len {
            let mut codeword = vec![0; data_volumes.len() + recovery_count];
            for (index, data) in data_volumes.iter().enumerate() {
                if let Some(data) = data {
                    codeword[index] = data.get(offset).copied().unwrap_or(0);
                }
            }
            for (index, data) in recovery_by_index.iter().enumerate() {
                if let Some(data) = data {
                    codeword[data_volumes.len() + index] = data[offset];
                }
            }
            coder.correct_erasures(&mut codeword, &erasures)?;
            for &index in &missing_data {
                out[index][offset] = codeword[index];
            }
        }

        Ok(out)
    }

    #[cfg(test)]
    mod tests {
        use super::{reconstruct_data_volumes, Error, RSCoder8};

        #[test]
        fn rs8_encoder_matches_unrar_generator_shape() {
            let coder = RSCoder8::new(11).unwrap();
            assert_eq!(
                coder.generator,
                vec![97, 180, 203, 151, 195, 196, 219, 7, 113, 50, 69]
            );
        }

        #[test]
        fn rs8_reconstructs_single_erased_data_symbol() {
            let coder = RSCoder8::new(4).unwrap();
            let data = b"rar recovery data";
            let parity = coder.encode(data);
            let mut codeword = [data.as_slice(), parity.as_slice()].concat();
            let original = codeword.clone();
            codeword[3] ^= 0xa5;

            coder.correct_erasures(&mut codeword, &[3]).unwrap();

            assert_eq!(codeword, original);
        }

        #[test]
        fn rs8_reconstructs_multiple_erased_symbols_including_parity() {
            let coder = RSCoder8::new(5).unwrap();
            let data = b"rar3-rs8";
            let parity = coder.encode(data);
            let mut codeword = [data.as_slice(), parity.as_slice()].concat();
            let original = codeword.clone();
            codeword[1] = 0;
            codeword[7] = 0;
            codeword[10] = 0;

            coder.correct_erasures(&mut codeword, &[1, 7, 10]).unwrap();

            assert_eq!(codeword, original);
        }

        #[test]
        fn rs8_rejects_more_erasures_than_parity_symbols() {
            let coder = RSCoder8::new(2).unwrap();
            let mut codeword = b"abcde".to_vec();

            assert_eq!(
                coder.correct_erasures(&mut codeword, &[0, 1, 2]),
                Err(Error::TooManyErasures)
            );
        }

        #[test]
        fn rev3_reconstructs_missing_data_volume_from_recovery_volume() {
            let data = [
                b"volume-one".as_slice(),
                b"volume-two".as_slice(),
                b"volume-three".as_slice(),
            ];
            let recovery_count = 2;
            let coder = RSCoder8::new(recovery_count).unwrap();
            let shard_len = data.iter().map(|shard| shard.len()).max().unwrap();
            let mut recovery = vec![vec![0; shard_len]; recovery_count];
            for offset in 0..shard_len {
                let column: Vec<_> = data
                    .iter()
                    .map(|shard| shard.get(offset).copied().unwrap_or(0))
                    .collect();
                let encoded = coder.encode(&column);
                for (index, byte) in encoded.into_iter().enumerate() {
                    recovery[index][offset] = byte;
                }
            }

            let repaired = reconstruct_data_volumes(
                &[Some(data[0]), None, Some(data[2])],
                recovery_count,
                &[(0, recovery[0].as_slice())],
            )
            .unwrap();

            assert_eq!(&repaired[1][..data[1].len()], data[1]);
        }
    }
}

pub mod rar5 {
    const CRC64_XZ_POLY: u64 = 0xc96c_5795_d787_0f42;
    const CRC64_XZ_INIT: u64 = 0xffff_ffff_ffff_ffff;
    const FIELD_SIZE: usize = 65_535;
    const FIELD_MASK: u32 = 0xffff;
    const PRIMITIVE_POLYNOMIAL: u32 = 0x1100b;
    const ZERO_LOG_SENTINEL: u32 = (FIELD_SIZE * 2) as u32;
    const MAX_WINRAR602_DATA_SHARDS: u64 = 200;
    const KIB: u64 = 1024;
    const RAR5_RECOVERY_CHUNK_FIXED_HEADER_SIZE: u64 = 0x48;

    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum Error {
        BadRecoveryChunk,
        OddShardSize,
        PlanOverflow,
        PrefixExceedsPlan,
        TooManyDamagedShards,
        ShardSizeMismatch,
        TooManyShards,
        SingularElement,
    }

    pub type Result<T> = std::result::Result<T, Error>;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct InlineRecoveryPlan {
        pub data_shards: u64,
        pub recovery_shards: u64,
        pub group_count: u64,
        pub header_size: u64,
        pub shard_size: u64,
    }

    impl InlineRecoveryPlan {
        pub fn payload_size(self) -> Result<u64> {
            self.recovery_shards
                .checked_mul(self.shard_size)
                .ok_or(Error::PlanOverflow)
        }
    }

    pub fn plan_inline_recovery(
        archive_size: u64,
        recovery_percent: u64,
    ) -> Result<InlineRecoveryPlan> {
        let pct = recovery_percent.min(100);
        let data_shards = if archive_size >= 200 * KIB {
            MAX_WINRAR602_DATA_SHARDS
        } else {
            archive_size.div_ceil(KIB).max(1)
        };
        let mut recovery_shards = (2 * pct * data_shards) / 200;
        recovery_shards = recovery_shards.min(data_shards);
        if recovery_shards == 0 && archive_size < 200 * KIB {
            recovery_shards = 1;
        }
        let mut group_count = archive_size.div_ceil(data_shards);
        group_count += group_count & 1;
        let scale_factor = group_count.div_ceil(0x10000).max(1);
        let header_size = (data_shards
            .checked_mul(8)
            .and_then(|value| value.checked_add(RAR5_RECOVERY_CHUNK_FIXED_HEADER_SIZE))
            .ok_or(Error::PlanOverflow)?)
        .checked_mul(scale_factor)
        .ok_or(Error::PlanOverflow)?;
        let shard_size = header_size
            .checked_add(group_count)
            .ok_or(Error::PlanOverflow)?;

        Ok(InlineRecoveryPlan {
            data_shards,
            recovery_shards,
            group_count,
            header_size,
            shard_size,
        })
    }

    pub fn crc64_xz(data: &[u8]) -> u64 {
        crc64_update(data, CRC64_XZ_INIT) ^ CRC64_XZ_INIT
    }

    fn crc64_update(data: &[u8], initial: u64) -> u64 {
        let mut crc = initial;
        for &byte in data {
            crc ^= byte as u64;
            for _ in 0..8 {
                let mask = 0u64.wrapping_sub(crc & 1);
                crc = (crc >> 1) ^ (CRC64_XZ_POLY & mask);
            }
        }
        crc
    }

    pub fn crc64_rar_state(data: &[u8]) -> u64 {
        crc64_update(data, 0)
    }

    pub fn split_prefix_shard_ranges(
        prefix_len: usize,
        plan: InlineRecoveryPlan,
    ) -> Result<Vec<std::ops::Range<usize>>> {
        let data_shards = usize::try_from(plan.data_shards).map_err(|_| Error::PlanOverflow)?;
        let group_count = usize::try_from(plan.group_count).map_err(|_| Error::PlanOverflow)?;
        let capacity = data_shards
            .checked_mul(group_count)
            .ok_or(Error::PlanOverflow)?;
        if prefix_len > capacity {
            return Err(Error::PrefixExceedsPlan);
        }

        let mut ranges = Vec::with_capacity(data_shards);
        for shard_index in 0..data_shards {
            let start = shard_index
                .checked_mul(group_count)
                .ok_or(Error::PlanOverflow)?;
            let end = start.saturating_add(group_count).min(prefix_len);
            ranges.push(start..end);
        }
        Ok(ranges)
    }

    pub fn split_prefix_shards(prefix: &[u8], plan: InlineRecoveryPlan) -> Result<Vec<Vec<u8>>> {
        let group_count = usize::try_from(plan.group_count).map_err(|_| Error::PlanOverflow)?;
        let ranges = split_prefix_shard_ranges(prefix.len(), plan)?;
        let mut shards = Vec::with_capacity(ranges.len());
        for range in ranges {
            let mut shard = vec![0u8; group_count];
            if range.start < range.end {
                shard[..range.end - range.start].copy_from_slice(&prefix[range]);
            }
            shards.push(shard);
        }
        Ok(shards)
    }

    pub fn encode_inline_recovery_parity(
        archive_prefix: &[u8],
        recovery_percent: u64,
    ) -> Result<(InlineRecoveryPlan, Vec<Vec<u8>>)> {
        let plan = plan_inline_recovery(archive_prefix.len() as u64, recovery_percent)?;
        let shards = split_prefix_shards(archive_prefix, plan)?;
        let shard_refs: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();
        let parity = encode_parity_shards(
            &shard_refs,
            usize::try_from(plan.recovery_shards).map_err(|_| Error::PlanOverflow)?,
        )?;
        Ok((plan, parity))
    }

    pub fn build_structural_inline_recovery_data(
        archive_prefix: &[u8],
        recovery_percent: u64,
    ) -> Result<Vec<u8>> {
        let (plan, parity) = encode_inline_recovery_parity(archive_prefix, recovery_percent)?;
        let shard_ranges = split_prefix_shard_ranges(archive_prefix.len(), plan)?;
        let total_len = usize::try_from(plan.payload_size()?).map_err(|_| Error::PlanOverflow)?;
        let header_size = usize::try_from(plan.header_size).map_err(|_| Error::PlanOverflow)?;
        let shard_size = usize::try_from(plan.shard_size).map_err(|_| Error::PlanOverflow)?;
        let data_shards = usize::try_from(plan.data_shards).map_err(|_| Error::PlanOverflow)?;
        let recovery_shards =
            usize::try_from(plan.recovery_shards).map_err(|_| Error::PlanOverflow)?;
        let total_size = u32::try_from(plan.shard_size).map_err(|_| Error::PlanOverflow)?;
        let header_size_u32 = u32::try_from(plan.header_size).map_err(|_| Error::PlanOverflow)?;
        let data_shards_u16 = u16::try_from(plan.data_shards).map_err(|_| Error::PlanOverflow)?;
        let recovery_shards_u16 =
            u16::try_from(plan.recovery_shards).map_err(|_| Error::PlanOverflow)?;
        let chunk_data_extent = shard_ranges.last().map_or(0usize, std::ops::Range::len);
        let chunk_data_extent_u32 =
            u32::try_from(chunk_data_extent).map_err(|_| Error::PlanOverflow)?;
        let data_shard_states: Vec<u64> = shard_ranges
            .iter()
            .map(|range| crc64_rar_state(&archive_prefix[range.clone()]))
            .collect();
        let final_state = parity
            .first()
            .map(|payload| crc64_rar_state(payload))
            .unwrap_or(0);

        let mut out = Vec::with_capacity(total_len);
        for (shard_index, payload) in parity.iter().enumerate() {
            if payload.len() + header_size != shard_size {
                return Err(Error::PlanOverflow);
            }

            let chunk_start = out.len();
            out.extend_from_slice(b"{RB}");
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&total_size.to_le_bytes());
            out.extend_from_slice(&header_size_u32.to_le_bytes());
            out.push(1);
            out.push(1);
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&chunk_data_extent_u32.to_le_bytes());
            out.extend_from_slice(&(archive_prefix.len() as u64).to_le_bytes());
            out.extend_from_slice(&plan.group_count.to_le_bytes());
            out.extend_from_slice(&plan.shard_size.to_le_bytes());
            out.extend_from_slice(&data_shards_u16.to_le_bytes());
            out.extend_from_slice(&recovery_shards_u16.to_le_bytes());
            out.extend_from_slice(
                &u16::try_from(shard_index)
                    .map_err(|_| Error::PlanOverflow)?
                    .to_le_bytes(),
            );
            for &state in &data_shard_states {
                out.extend_from_slice(&state.to_le_bytes());
            }
            out.extend_from_slice(&final_state.to_le_bytes());
            debug_assert_eq!(out.len() - chunk_start, header_size);
            out.extend_from_slice(payload);
            debug_assert_eq!(out.len() - chunk_start, shard_size);

            let crc = crc64_xz(&out[chunk_start + 0x0c..chunk_start + shard_size]);
            out[chunk_start + 0x04..chunk_start + 0x0c].copy_from_slice(&crc.to_le_bytes());
        }
        debug_assert_eq!(out.len(), total_len);
        debug_assert_eq!(parity.len(), recovery_shards);
        debug_assert_eq!(data_shard_states.len(), data_shards);
        Ok(out)
    }

    #[derive(Debug, Clone)]
    struct InlineRecoveryChunk {
        plan: InlineRecoveryPlan,
        protected_size: u64,
        shard_index: usize,
        data_shard_states: Vec<u64>,
        parity: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    struct FoundInlineRecoveryChunk {
        offset: usize,
        chunk: InlineRecoveryChunk,
    }

    pub fn repair_inline_recovery_prefix(
        archive_prefix: &[u8],
        recovery_data: &[u8],
    ) -> Result<Vec<u8>> {
        let chunks = parse_available_inline_recovery_chunks(recovery_data)?;
        let first = chunks.first().ok_or(Error::BadRecoveryChunk)?;
        let plan = first.plan;
        if first.protected_size != archive_prefix.len() as u64 {
            return Err(Error::BadRecoveryChunk);
        }
        if chunks.iter().any(|chunk| {
            chunk.plan != plan
                || chunk.protected_size != first.protected_size
                || chunk.data_shard_states != first.data_shard_states
        }) {
            return Err(Error::BadRecoveryChunk);
        }

        let mut data_shards = split_prefix_shards(archive_prefix, plan)?;
        let shard_ranges = split_prefix_shard_ranges(archive_prefix.len(), plan)?;
        let damaged: Vec<usize> = shard_ranges
            .iter()
            .enumerate()
            .filter_map(|(index, range)| {
                (crc64_rar_state(&archive_prefix[range.clone()]) != first.data_shard_states[index])
                    .then_some(index)
            })
            .collect();
        if damaged.is_empty() {
            return Ok(archive_prefix.to_vec());
        }
        if damaged.len() > chunks.len() {
            return Err(Error::TooManyDamagedShards);
        }

        let recovery_rows: Vec<_> = chunks[..damaged.len()]
            .iter()
            .map(|chunk| (chunk.shard_index, chunk.parity.as_slice()))
            .collect();
        recover_damaged_shards(&mut data_shards, &damaged, &recovery_rows)?;

        let mut repaired = Vec::with_capacity(archive_prefix.len());
        for (shard, range) in data_shards.iter().zip(shard_ranges) {
            repaired.extend_from_slice(&shard[..range.len()]);
        }
        debug_assert_eq!(repaired.len(), archive_prefix.len());
        Ok(repaired)
    }

    pub fn repair_inline_recovery_archive(input: &[u8]) -> Result<Vec<u8>> {
        let chunks = find_inline_recovery_chunks(input)?;
        let first = chunks.first().ok_or(Error::BadRecoveryChunk)?;
        let protected_size =
            usize::try_from(first.chunk.protected_size).map_err(|_| Error::PlanOverflow)?;
        if protected_size > input.len() {
            return Err(Error::BadRecoveryChunk);
        }
        let mut recovery_data = Vec::with_capacity(
            chunks
                .iter()
                .map(|found| found.chunk.plan.shard_size as usize)
                .sum(),
        );
        for found in &chunks {
            append_inline_recovery_chunk(input, found, &mut recovery_data)?;
        }
        let repaired_prefix =
            repair_inline_recovery_prefix(&input[..protected_size], &recovery_data)?;
        if repaired_prefix == input[..protected_size] {
            return Err(Error::BadRecoveryChunk);
        }
        let mut repaired = input.to_vec();
        repaired[..protected_size].copy_from_slice(&repaired_prefix);
        Ok(repaired)
    }

    fn find_inline_recovery_chunks(input: &[u8]) -> Result<Vec<FoundInlineRecoveryChunk>> {
        let mut chunks = Vec::new();
        let mut offset = 0usize;
        while let Some(relative) = find_recovery_marker(&input[offset..]) {
            let start = offset + relative;
            if let Ok(chunk) = parse_inline_recovery_chunk(&input[start..]) {
                let shard_size =
                    usize::try_from(chunk.plan.shard_size).map_err(|_| Error::PlanOverflow)?;
                if input.len().saturating_sub(start) >= shard_size {
                    chunks.push(FoundInlineRecoveryChunk {
                        offset: start,
                        chunk,
                    });
                    offset = start + shard_size;
                    continue;
                }
            }
            offset = start + 1;
        }
        if chunks.is_empty() {
            return Err(Error::BadRecoveryChunk);
        }
        Ok(chunks)
    }

    fn find_recovery_marker(input: &[u8]) -> Option<usize> {
        let mut offset = 0usize;
        while offset + 4 <= input.len() {
            let relative = input[offset..].iter().position(|&byte| byte == b'{')?;
            offset += relative;
            if input.get(offset..offset + 4) == Some(b"{RB}") {
                return Some(offset);
            }
            offset += 1;
        }
        None
    }

    fn append_inline_recovery_chunk(
        input: &[u8],
        found: &FoundInlineRecoveryChunk,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        let shard_size =
            usize::try_from(found.chunk.plan.shard_size).map_err(|_| Error::PlanOverflow)?;
        let start = found.offset;
        let end = start.checked_add(shard_size).ok_or(Error::PlanOverflow)?;
        out.extend_from_slice(input.get(start..end).ok_or(Error::BadRecoveryChunk)?);
        Ok(())
    }

    pub fn reconstruct_data_shards(
        data_shards: &[Option<&[u8]>],
        recovery_shards: &[(usize, &[u8])],
    ) -> Result<Vec<Vec<u8>>> {
        if data_shards.is_empty() {
            return Err(Error::TooManyShards);
        }
        let shard_len = recovery_shards
            .first()
            .map(|(_, shard)| shard.len())
            .or_else(|| data_shards.iter().flatten().map(|shard| shard.len()).max())
            .ok_or(Error::TooManyDamagedShards)?;
        if shard_len % 2 != 0 {
            return Err(Error::OddShardSize);
        }
        if recovery_shards
            .iter()
            .any(|(_, shard)| shard.len() != shard_len)
        {
            return Err(Error::ShardSizeMismatch);
        }

        let mut out = Vec::with_capacity(data_shards.len());
        let mut missing = Vec::new();
        for (index, shard) in data_shards.iter().enumerate() {
            let mut padded = vec![0; shard_len];
            if let Some(shard) = shard {
                if shard.len() > shard_len {
                    return Err(Error::ShardSizeMismatch);
                }
                padded[..shard.len()].copy_from_slice(shard);
            } else {
                missing.push(index);
            }
            out.push(padded);
        }
        if missing.is_empty() {
            return Ok(out);
        }
        if missing.len() > recovery_shards.len() {
            return Err(Error::TooManyDamagedShards);
        }
        recover_damaged_shards(&mut out, &missing, &recovery_shards[..missing.len()])?;
        Ok(out)
    }

    fn parse_available_inline_recovery_chunks(
        recovery_data: &[u8],
    ) -> Result<Vec<InlineRecoveryChunk>> {
        Ok(find_inline_recovery_chunks(recovery_data)?
            .into_iter()
            .map(|found| found.chunk)
            .collect())
    }

    fn parse_inline_recovery_chunk(input: &[u8]) -> Result<InlineRecoveryChunk> {
        if input.len() < 0x48 || &input[..4] != b"{RB}" {
            return Err(Error::BadRecoveryChunk);
        }
        let total_size = read_u32(input, 0x0c)? as u64;
        let header_size = read_u32(input, 0x10)? as u64;
        if header_size < RAR5_RECOVERY_CHUNK_FIXED_HEADER_SIZE || header_size > total_size {
            return Err(Error::BadRecoveryChunk);
        }
        let total_size_usize = usize::try_from(total_size).map_err(|_| Error::PlanOverflow)?;
        let header_size_usize = usize::try_from(header_size).map_err(|_| Error::PlanOverflow)?;
        if input.len() < total_size_usize {
            return Err(Error::BadRecoveryChunk);
        }
        let expected_crc = read_u64(input, 0x04)?;
        let actual_crc = crc64_xz(&input[0x0c..total_size_usize]);
        if actual_crc != expected_crc {
            return Err(Error::BadRecoveryChunk);
        }
        if input[0x14] != 1 || input[0x15] != 1 {
            return Err(Error::BadRecoveryChunk);
        }

        let protected_size = read_u64(input, 0x22)?;
        let group_count = read_u64(input, 0x2a)?;
        let shard_size = read_u64(input, 0x32)?;
        let data_shards = u16::from_le_bytes(input[0x3a..0x3c].try_into().unwrap()) as u64;
        let recovery_shards = u16::from_le_bytes(input[0x3c..0x3e].try_into().unwrap()) as u64;
        let shard_index = u16::from_le_bytes(input[0x3e..0x40].try_into().unwrap()) as usize;
        let plan = InlineRecoveryPlan {
            data_shards,
            recovery_shards,
            group_count,
            header_size,
            shard_size,
        };
        if plan.payload_size()?
            != recovery_shards
                .checked_mul(shard_size)
                .ok_or(Error::PlanOverflow)?
            || shard_size != total_size
            || shard_index >= recovery_shards as usize
            || header_size_usize != 0x48 + data_shards as usize * 8
            || total_size_usize < header_size_usize
        {
            return Err(Error::BadRecoveryChunk);
        }

        let mut data_shard_states = Vec::with_capacity(data_shards as usize);
        let mut pos = 0x40;
        for _ in 0..data_shards {
            data_shard_states.push(read_u64(input, pos)?);
            pos += 8;
        }
        let _final_state = read_u64(input, pos)?;
        let parity = input[header_size_usize..total_size_usize].to_vec();
        if parity.len() as u64 != group_count {
            return Err(Error::BadRecoveryChunk);
        }
        Ok(InlineRecoveryChunk {
            plan,
            protected_size,
            shard_index,
            data_shard_states,
            parity,
        })
    }

    fn recover_damaged_shards(
        data_shards: &mut [Vec<u8>],
        damaged: &[usize],
        recovery_shards: &[(usize, &[u8])],
    ) -> Result<()> {
        let data_count = data_shards.len();
        let recovery_count = recovery_shards
            .iter()
            .map(|(row, _)| row + 1)
            .max()
            .ok_or(Error::TooManyDamagedShards)?;
        let matrix = make_encoder_matrix(data_count, recovery_count)?;
        let equations: Vec<Vec<u16>> = recovery_shards
            .iter()
            .map(|&(row_index, _)| {
                damaged
                    .iter()
                    .map(|&data_index| matrix[row_index][data_index])
                    .collect()
            })
            .collect();
        let mut damaged_lookup = vec![false; data_count];
        for &data_index in damaged {
            if data_index >= data_count {
                return Err(Error::TooManyDamagedShards);
            }
            damaged_lookup[data_index] = true;
        }

        let shard_len = data_shards.first().ok_or(Error::TooManyShards)?.len();
        let gf = Gf16::new();
        for word_offset in (0..shard_len).step_by(2) {
            let mut rhs = Vec::with_capacity(recovery_shards.len());
            for &(row_index, parity) in recovery_shards {
                let mut value = u16::from_le_bytes([parity[word_offset], parity[word_offset + 1]]);
                for (data_index, shard) in data_shards.iter().enumerate() {
                    if damaged_lookup[data_index] {
                        continue;
                    }
                    let data_symbol =
                        u16::from_le_bytes([shard[word_offset], shard[word_offset + 1]]);
                    value ^= gf.mul(matrix[row_index][data_index], data_symbol);
                }
                rhs.push(value);
            }
            let solved = solve_linear_system(&gf, equations.clone(), rhs)?;
            for (&data_index, &symbol) in damaged.iter().zip(&solved) {
                data_shards[data_index][word_offset..word_offset + 2]
                    .copy_from_slice(&symbol.to_le_bytes());
            }
        }
        Ok(())
    }

    fn solve_linear_system(
        gf: &Gf16,
        mut matrix: Vec<Vec<u16>>,
        mut rhs: Vec<u16>,
    ) -> Result<Vec<u16>> {
        let n = rhs.len();
        if matrix.len() != n || matrix.iter().any(|row| row.len() != n) {
            return Err(Error::BadRecoveryChunk);
        }
        for col in 0..n {
            let pivot = (col..n)
                .find(|&row| matrix[row][col] != 0)
                .ok_or(Error::SingularElement)?;
            matrix.swap(col, pivot);
            rhs.swap(col, pivot);
            let inv = gf.inv(matrix[col][col])?;
            for value in &mut matrix[col][col..] {
                *value = gf.mul(*value, inv);
            }
            rhs[col] = gf.mul(rhs[col], inv);

            for row in 0..n {
                if row == col {
                    continue;
                }
                let factor = matrix[row][col];
                if factor == 0 {
                    continue;
                }
                for c in col..n {
                    matrix[row][c] ^= gf.mul(factor, matrix[col][c]);
                }
                rhs[row] ^= gf.mul(factor, rhs[col]);
            }
        }
        Ok(rhs)
    }

    fn read_u32(input: &[u8], offset: usize) -> Result<u32> {
        input
            .get(offset..offset + 4)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or(Error::BadRecoveryChunk)
    }

    fn read_u64(input: &[u8], offset: usize) -> Result<u64> {
        input
            .get(offset..offset + 8)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or(Error::BadRecoveryChunk)
    }

    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct Gf16 {
        exp: Box<[u16]>,
        log: Box<[u32]>,
    }

    impl Gf16 {
        pub fn new() -> Self {
            let mut exp = vec![0u16; FIELD_SIZE * 4 + 1];
            let mut log = vec![0u32; FIELD_SIZE + 1];
            let mut value = 1u32;
            for power in 0..FIELD_SIZE {
                log[value as usize] = power as u32;
                exp[power] = value as u16;
                exp[power + FIELD_SIZE] = value as u16;
                value <<= 1;
                if value > FIELD_MASK {
                    value ^= PRIMITIVE_POLYNOMIAL;
                }
            }
            log[0] = ZERO_LOG_SENTINEL;
            Self {
                exp: exp.into_boxed_slice(),
                log: log.into_boxed_slice(),
            }
        }

        pub fn add(&self, left: u16, right: u16) -> u16 {
            left ^ right
        }

        pub fn mul(&self, left: u16, right: u16) -> u16 {
            if left == 0 || right == 0 {
                return 0;
            }
            let index = self.log[left as usize] + self.log[right as usize];
            self.exp[index as usize]
        }

        pub fn inv(&self, value: u16) -> Result<u16> {
            if value == 0 {
                return Err(Error::SingularElement);
            }
            let index = FIELD_SIZE as u32 - self.log[value as usize];
            Ok(self.exp[index as usize])
        }

        pub fn div(&self, numerator: u16, denominator: u16) -> Result<u16> {
            Ok(self.mul(numerator, self.inv(denominator)?))
        }
    }

    impl Default for Gf16 {
        fn default() -> Self {
            Self::new()
        }
    }

    pub fn make_encoder_matrix(
        data_shards: usize,
        recovery_shards: usize,
    ) -> Result<Vec<Vec<u16>>> {
        if data_shards == 0 || recovery_shards == 0 || data_shards + recovery_shards > FIELD_SIZE {
            return Err(Error::TooManyShards);
        }
        let gf = Gf16::new();
        let mut matrix = vec![vec![0u16; data_shards]; recovery_shards];
        for (i, row) in matrix.iter_mut().enumerate() {
            for (j, cell) in row.iter_mut().enumerate() {
                let denominator = ((i + data_shards) ^ j) as u16;
                *cell = gf.inv(denominator)?;
            }
        }
        Ok(matrix)
    }

    pub fn encode_parity_shards(data: &[&[u8]], recovery_shards: usize) -> Result<Vec<Vec<u8>>> {
        let Some(first) = data.first() else {
            return Err(Error::TooManyShards);
        };
        if first.len() % 2 != 0 {
            return Err(Error::OddShardSize);
        }
        if data.iter().any(|shard| shard.len() != first.len()) {
            return Err(Error::ShardSizeMismatch);
        }

        let matrix = make_encoder_matrix(data.len(), recovery_shards)?;
        let gf = Gf16::new();
        let mut parity = vec![vec![0u8; first.len()]; recovery_shards];
        for (recovery_index, row) in matrix.iter().enumerate() {
            for word_offset in (0..first.len()).step_by(2) {
                let mut symbol = 0u16;
                for (data_index, shard) in data.iter().enumerate() {
                    let data_symbol =
                        u16::from_le_bytes([shard[word_offset], shard[word_offset + 1]]);
                    symbol ^= gf.mul(row[data_index], data_symbol);
                }
                parity[recovery_index][word_offset..word_offset + 2]
                    .copy_from_slice(&symbol.to_le_bytes());
            }
        }
        Ok(parity)
    }

    #[cfg(test)]
    mod tests {
        use super::{
            build_structural_inline_recovery_data, crc64_rar_state, crc64_xz,
            encode_inline_recovery_parity, encode_parity_shards, make_encoder_matrix,
            plan_inline_recovery, reconstruct_data_shards, repair_inline_recovery_archive,
            repair_inline_recovery_prefix, split_prefix_shard_ranges, split_prefix_shards, Error,
            Gf16, InlineRecoveryPlan,
        };

        #[test]
        fn rar5_inline_recovery_plan_matches_fixture_formula_examples() {
            assert_eq!(
                plan_inline_recovery(65_681, 5).unwrap(),
                InlineRecoveryPlan {
                    data_shards: 65,
                    recovery_shards: 3,
                    group_count: 1012,
                    header_size: 592,
                    shard_size: 1604,
                }
            );
            assert_eq!(
                plan_inline_recovery(65_681, 20).unwrap(),
                InlineRecoveryPlan {
                    data_shards: 65,
                    recovery_shards: 13,
                    group_count: 1012,
                    header_size: 592,
                    shard_size: 1604,
                }
            );
        }

        #[test]
        fn rar5_inline_recovery_plan_handles_clamps_and_large_prefixes() {
            assert_eq!(
                plan_inline_recovery(0, 0).unwrap(),
                InlineRecoveryPlan {
                    data_shards: 1,
                    recovery_shards: 1,
                    group_count: 0,
                    header_size: 80,
                    shard_size: 80,
                }
            );
            assert_eq!(
                plan_inline_recovery(200 * 1024, 1000).unwrap(),
                InlineRecoveryPlan {
                    data_shards: 200,
                    recovery_shards: 200,
                    group_count: 1024,
                    header_size: 1672,
                    shard_size: 2696,
                }
            );
        }

        #[test]
        fn gf16_matches_rar5_polynomial_wrap() {
            let gf = Gf16::new();

            assert_eq!(gf.mul(0x8000, 2), 0x100b);
            assert_eq!(gf.mul(0, 0x1234), 0);
            assert_eq!(gf.mul(0x1234, 0), 0);
            assert_eq!(gf.mul(0, 0), 0);
            assert_eq!(gf.mul(1, 0x1234), 0x1234);
        }

        #[test]
        fn crc64_xz_matches_reference_vectors() {
            assert_eq!(crc64_xz(b""), 0);
            assert_eq!(crc64_xz(b"123456789"), 0x995d_c9bb_df19_39fa);
            assert_eq!(crc64_xz(b"testtesttest"), 0x7b1c_2d23_0ede_b436);
        }

        #[test]
        fn raw_crc64_state_matches_reference_vector() {
            assert_eq!(crc64_rar_state(b""), 0);
            assert_eq!(crc64_rar_state(b"te\x80st"), 0xb5db_f958_3a6e_ed4a);
        }

        #[test]
        fn rar5_prefix_split_produces_even_padded_data_shards() {
            let plan = InlineRecoveryPlan {
                data_shards: 3,
                recovery_shards: 1,
                group_count: 4,
                header_size: 96,
                shard_size: 100,
            };
            let shards = split_prefix_shards(b"abcdefghij", plan).unwrap();

            assert_eq!(
                shards,
                vec![b"abcd".to_vec(), b"efgh".to_vec(), b"ij\0\0".to_vec()]
            );
        }

        #[test]
        fn rar5_prefix_split_rejects_prefix_larger_than_plan_capacity() {
            let plan = InlineRecoveryPlan {
                data_shards: 2,
                recovery_shards: 1,
                group_count: 2,
                header_size: 88,
                shard_size: 90,
            };

            assert_eq!(
                split_prefix_shards(b"abcde", plan),
                Err(Error::PrefixExceedsPlan)
            );
        }

        #[test]
        fn gf16_inverse_round_trips_nonzero_elements() {
            let gf = Gf16::new();

            for value in [1, 2, 3, 0x100b, 0x8000, 0xffff] {
                let inverse = gf.inv(value).unwrap();
                assert_eq!(gf.mul(value, inverse), 1);
            }
            assert_eq!(gf.inv(0), Err(Error::SingularElement));
        }

        #[test]
        fn rar5_cauchy_encoder_matrix_uses_inverse_xor_denominators() {
            let gf = Gf16::new();
            let matrix = make_encoder_matrix(3, 2).unwrap();

            assert_eq!(matrix.len(), 2);
            assert_eq!(matrix[0].len(), 3);
            for (i, row) in matrix.iter().enumerate() {
                for (j, &cell) in row.iter().enumerate() {
                    let denominator = ((i + 3) ^ j) as u16;
                    assert_eq!(gf.mul(cell, denominator), 1);
                }
            }
        }

        #[test]
        fn rar5_cauchy_encoder_matrix_rejects_impossible_shard_counts() {
            assert_eq!(make_encoder_matrix(0, 1), Err(Error::TooManyShards));
            assert_eq!(make_encoder_matrix(1, 0), Err(Error::TooManyShards));
            assert_eq!(make_encoder_matrix(65535, 1), Err(Error::TooManyShards));
        }

        #[test]
        fn rar5_parity_encoder_generates_systematic_recovery_shards() {
            let first = [1, 0, 2, 0, 3, 0, 4, 0];
            let parity = encode_parity_shards(&[&first], 1).unwrap();

            assert_eq!(parity, [first.to_vec()]);
        }

        #[test]
        fn rar5_parity_encoder_applies_cauchy_matrix_coefficients() {
            let gf = Gf16::new();
            let first = [1, 0, 2, 0];
            let second = [3, 0, 4, 0];
            let matrix = make_encoder_matrix(2, 2).unwrap();
            let parity = encode_parity_shards(&[&first, &second], 2).unwrap();

            for recovery_index in 0..2 {
                for word_index in 0..2 {
                    let offset = word_index * 2;
                    let left = u16::from_le_bytes([first[offset], first[offset + 1]]);
                    let right = u16::from_le_bytes([second[offset], second[offset + 1]]);
                    let expected = gf.mul(matrix[recovery_index][0], left)
                        ^ gf.mul(matrix[recovery_index][1], right);
                    assert_eq!(
                        u16::from_le_bytes([
                            parity[recovery_index][offset],
                            parity[recovery_index][offset + 1],
                        ]),
                        expected
                    );
                }
            }
        }

        #[test]
        fn rar5_inline_recovery_parity_splits_and_encodes_prefix() {
            let prefix = b"RAR5 inline recovery parity payload input";
            let (plan, parity) = encode_inline_recovery_parity(prefix, 10).unwrap();

            assert_eq!(plan, plan_inline_recovery(prefix.len() as u64, 10).unwrap());
            assert_eq!(parity.len(), plan.recovery_shards as usize);
            assert!(parity
                .iter()
                .all(|shard| shard.len() == plan.group_count as usize));

            let data_shards = split_prefix_shards(prefix, plan).unwrap();
            let shard_refs: Vec<&[u8]> = data_shards.iter().map(Vec::as_slice).collect();
            assert_eq!(
                parity,
                encode_parity_shards(&shard_refs, plan.recovery_shards as usize).unwrap()
            );
        }

        #[test]
        fn rar5_structural_inline_recovery_data_writes_chunks_and_crc64() {
            let prefix = b"RAR5 structural inline recovery data";
            let (plan, parity) = encode_inline_recovery_parity(prefix, 10).unwrap();
            let data = build_structural_inline_recovery_data(prefix, 10).unwrap();

            assert_eq!(data.len(), plan.payload_size().unwrap() as usize);
            for (shard_index, payload) in parity.iter().enumerate() {
                let chunk_start = shard_index * plan.shard_size as usize;
                let chunk = &data[chunk_start..chunk_start + plan.shard_size as usize];
                assert_eq!(&chunk[..4], b"{RB}");
                assert_eq!(
                    u64::from_le_bytes(chunk[4..12].try_into().unwrap()),
                    crc64_xz(&chunk[0x0c..])
                );
                assert_eq!(
                    u32::from_le_bytes(chunk[0x0c..0x10].try_into().unwrap()) as u64,
                    plan.shard_size
                );
                assert_eq!(
                    u32::from_le_bytes(chunk[0x10..0x14].try_into().unwrap()) as u64,
                    plan.header_size
                );
                assert_eq!(chunk[0x14], 1);
                assert_eq!(chunk[0x15], 1);
                assert_eq!(
                    u64::from_le_bytes(chunk[0x22..0x2a].try_into().unwrap()),
                    prefix.len() as u64
                );
                assert_eq!(
                    u16::from_le_bytes(chunk[0x3e..0x40].try_into().unwrap()) as usize,
                    shard_index
                );
                let shard_ranges = split_prefix_shard_ranges(prefix.len(), plan).unwrap();
                assert_eq!(
                    u32::from_le_bytes(chunk[0x1e..0x22].try_into().unwrap()) as usize,
                    shard_ranges.last().unwrap().len()
                );
                for (data_index, range) in shard_ranges.iter().enumerate() {
                    let state_offset = 0x40 + data_index * 8;
                    assert_eq!(
                        u64::from_le_bytes(
                            chunk[state_offset..state_offset + 8].try_into().unwrap()
                        ),
                        crc64_rar_state(&prefix[range.clone()])
                    );
                }
                assert_eq!(&chunk[plan.header_size as usize..], payload);
            }
        }

        #[test]
        fn rar5_structural_inline_recovery_uses_shared_final_state() {
            let prefix: Vec<u8> = (0..(256 * 1024)).map(|index| index as u8).collect();
            let (plan, parity) = encode_inline_recovery_parity(&prefix, 20).unwrap();
            assert!(plan.recovery_shards > 1);
            let data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
            let expected = crc64_rar_state(&parity[0]);

            for shard_index in 0..plan.recovery_shards as usize {
                let chunk_start = shard_index * plan.shard_size as usize;
                let final_state_offset = chunk_start + 0x40 + plan.data_shards as usize * 8;
                assert_eq!(
                    u64::from_le_bytes(
                        data[final_state_offset..final_state_offset + 8]
                            .try_into()
                            .unwrap()
                    ),
                    expected
                );
            }
        }

        #[test]
        fn rar5_parity_encoder_rejects_invalid_shard_shapes() {
            assert_eq!(encode_parity_shards(&[], 1), Err(Error::TooManyShards));
            assert_eq!(
                encode_parity_shards(&[&[1, 2, 3]], 1),
                Err(Error::OddShardSize)
            );
            assert_eq!(
                encode_parity_shards(&[&[1, 2], &[3, 4, 5, 6]], 1),
                Err(Error::ShardSizeMismatch)
            );
        }

        #[test]
        fn rar5_inline_recovery_repairs_single_damaged_data_shard() {
            let prefix: Vec<u8> = (0..32_000).map(|index| (index * 17) as u8).collect();
            let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
            let mut damaged = prefix.clone();
            damaged[1500..1537].fill(0xa5);

            let repaired = repair_inline_recovery_prefix(&damaged, &recovery_data).unwrap();

            assert_eq!(repaired, prefix);
        }

        #[test]
        fn rar5_inline_recovery_skips_damaged_recovery_chunks_if_enough_survive() {
            let prefix: Vec<u8> = (0..32_000).map(|index| (index * 13) as u8).collect();
            let mut recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
            recovery_data[0x48] ^= 0xff;
            let mut damaged = prefix.clone();
            damaged[1024..1300].fill(0xa5);

            let repaired = repair_inline_recovery_prefix(&damaged, &recovery_data).unwrap();

            assert_eq!(repaired, prefix);
        }

        #[test]
        fn rar5_inline_recovery_repairs_multiple_damaged_data_shards() {
            let prefix: Vec<u8> = (0..128_000).map(|index| (index * 31) as u8).collect();
            let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
            let mut damaged = prefix.clone();
            damaged[100..500].fill(0x11);
            damaged[4_000..4_400].fill(0x22);
            damaged[9_000..9_400].fill(0x33);

            let repaired = repair_inline_recovery_prefix(&damaged, &recovery_data).unwrap();

            assert_eq!(repaired, prefix);
        }

        #[test]
        fn rar5_inline_recovery_archive_scans_chunks_and_repairs_prefix() {
            let prefix: Vec<u8> = (0..32_000).map(|index| (index * 13) as u8).collect();
            let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
            let mut archive = prefix.clone();
            archive.extend_from_slice(b"service header bytes before chunks");
            archive.extend_from_slice(&recovery_data);
            archive.extend_from_slice(b"end bytes");
            let mut damaged = archive.clone();
            damaged[256..320].fill(0x5a);

            let repaired = repair_inline_recovery_archive(&damaged).unwrap();

            assert_eq!(repaired, archive);
        }

        #[test]
        fn rar5_inline_recovery_rejects_unrepairable_damage_count() {
            let prefix = b"small prefix with only one parity shard".repeat(100);
            let recovery_data = build_structural_inline_recovery_data(&prefix, 1).unwrap();
            let mut damaged = prefix.clone();
            damaged[0] ^= 0xff;
            damaged[1024] ^= 0xff;

            assert_eq!(
                repair_inline_recovery_prefix(&damaged, &recovery_data),
                Err(Error::TooManyDamagedShards)
            );
        }

        #[test]
        fn rar5_reconstruct_data_shards_repairs_missing_shards_from_parity() {
            let first = b"abcdefgh".to_vec();
            let second = b"ijklmnop".to_vec();
            let third = b"qrstuvwx".to_vec();
            let refs = [first.as_slice(), second.as_slice(), third.as_slice()];
            let parity = encode_parity_shards(&refs, 2).unwrap();

            let reconstructed = reconstruct_data_shards(
                &[Some(&first), None, Some(&third)],
                &[(0, parity[0].as_slice())],
            )
            .unwrap();

            assert_eq!(reconstructed[0], first);
            assert_eq!(reconstructed[1], second);
            assert_eq!(reconstructed[2], third);
        }

        #[test]
        fn rar5_reconstruct_data_shards_repairs_multiple_missing_shards() {
            let first = b"abcdefgh".to_vec();
            let second = b"ijklmnop".to_vec();
            let third = b"qrstuvwx".to_vec();
            let refs = [first.as_slice(), second.as_slice(), third.as_slice()];
            let parity = encode_parity_shards(&refs, 2).unwrap();

            let reconstructed = reconstruct_data_shards(
                &[None, Some(&second), None],
                &[(0, parity[0].as_slice()), (1, parity[1].as_slice())],
            )
            .unwrap();

            assert_eq!(reconstructed[0], first);
            assert_eq!(reconstructed[1], second);
            assert_eq!(reconstructed[2], third);
        }
    }
}
