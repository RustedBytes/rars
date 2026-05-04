//! Recovery-record primitives shared by RAR writer and repair code.
//!
//! RAR 5 recovery data uses GF(2^16) with reduction polynomial `0x1100b`
//! and a Cauchy encoder matrix. This crate intentionally exposes the field
//! and matrix building blocks before wiring them into archive serialization.

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
    pub enum Error {
        OddShardSize,
        PlanOverflow,
        PrefixExceedsPlan,
        ShardSizeMismatch,
        TooManyShards,
        SingularElement,
    }

    pub type Result<T> = std::result::Result<T, Error>;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            plan_inline_recovery, split_prefix_shard_ranges, split_prefix_shards, Error, Gf16,
            InlineRecoveryPlan,
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
    }
}
