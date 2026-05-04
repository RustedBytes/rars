use super::*;
use rars_codec::rar13::{unpack15_encode, Unpack15Encoder};
use rars_codec::rar20::{unpack20_encode_literals, Unpack20Encoder};
use rars_codec::rar29::{
    unpack29_encode_literals, unpack29_encode_with_audio_filter,
    unpack29_encode_with_audio_filter_range, unpack29_encode_with_delta_filter,
    unpack29_encode_with_delta_filter_range, unpack29_encode_with_e8_filter,
    unpack29_encode_with_e8_filter_range, unpack29_encode_with_e8e9_filter,
    unpack29_encode_with_e8e9_filter_range, unpack29_encode_with_itanium_filter,
    unpack29_encode_with_itanium_filter_range, unpack29_encode_with_rgb_filter,
    unpack29_encode_with_rgb_filter_range, Unpack29Encoder,
};
use std::ops::Range;

const AUTO_X86_CLUSTER_GAP: usize = 4096;
const AUTO_X86_RANGE_PADDING: usize = 16;
const AUTO_X86_MAX_RANGES: usize = 4;
const AUTO_RGB_WIDTHS: [usize; 4] = [24, 48, 96, 192];

pub fn write_stored_archive(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_stored_archive_with_comment(entries, options, None)
}

pub fn write_stored_archive_with_comment(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let has_file_comment = entries.iter().any(|entry| entry.file_comment.is_some());
    validate_stored_writer_options(options, archive_comment.is_some(), has_file_comment)?;
    if options.features.header_encryption {
        return write_header_encrypted_stored_archive(entries, options, archive_comment);
    }

    let mut out = Vec::new();
    out.extend_from_slice(RAR15_SIGNATURE);
    write_main_header(
        &mut out,
        if archive_comment.is_some() && uses_old_style_archive_comment(options.target) {
            MHD_COMMENT
        } else {
            0
        },
    );
    write_archive_comment(&mut out, archive_comment, options.target)?;
    for entry in entries {
        write_stored_entry(&mut out, entry, options.target)?;
    }
    Ok(out)
}

pub fn write_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_compressed_archive_with_comment(entries, options, None)
}

pub fn write_compressed_archive_with_comment(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let has_file_comment = entries.iter().any(|entry| entry.file_comment.is_some());
    validate_compressed_writer_options(options, archive_comment.is_some(), has_file_comment)?;
    if options.features.header_encryption {
        return write_header_encrypted_compressed_archive(entries, options, archive_comment);
    }

    let mut out = Vec::new();
    out.extend_from_slice(RAR15_SIGNATURE);
    let mut main_flags = if options.features.solid { MHD_SOLID } else { 0 };
    if archive_comment.is_some() && uses_old_style_archive_comment(options.target) {
        main_flags |= MHD_COMMENT;
    }
    write_main_header(&mut out, main_flags);
    write_archive_comment(&mut out, archive_comment, options.target)?;
    let mut solid_encoder = SolidEncoder::for_target(options.target, options.features.solid);
    for (index, entry) in entries.iter().enumerate() {
        let packed = encode_compressed_payload(entry.data, options.target, solid_encoder.as_mut())?;
        write_compressed_entry(
            &mut out,
            entry,
            &packed,
            options.target,
            options.features.solid && index != 0,
        )?;
    }
    Ok(out)
}

pub fn write_rar29_e8_filtered_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_rar29_x86_filtered_compressed_archive(entries, options, false)
}

pub fn write_rar29_e8e9_filtered_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_rar29_x86_filtered_compressed_archive(entries, options, true)
}

pub fn write_rar29_auto_filtered_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_rar29_filtered_archive(entries, options, |entry| {
        encode_rar29_auto_filtered_member(entry.data)
    })
}

pub fn write_rar29_e8_range_filtered_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    range: Range<usize>,
) -> Result<Vec<u8>> {
    write_rar29_x86_range_filtered_compressed_archive(entries, options, range, false)
}

pub fn write_rar29_e8e9_range_filtered_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    range: Range<usize>,
) -> Result<Vec<u8>> {
    write_rar29_x86_range_filtered_compressed_archive(entries, options, range, true)
}

pub fn write_rar29_delta_filtered_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    channels: usize,
) -> Result<Vec<u8>> {
    if channels == 0 || channels > 32 {
        return Err(Error::InvalidHeader(
            "RAR 2.9 DELTA filter channel count is invalid",
        ));
    }

    write_rar29_filtered_archive(entries, options, |entry| {
        unpack29_encode_with_delta_filter(entry.data, channels).map_err(Error::from)
    })
}

pub fn write_rar29_delta_range_filtered_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    range: Range<usize>,
    channels: usize,
) -> Result<Vec<u8>> {
    if channels == 0 || channels > 32 {
        return Err(Error::InvalidHeader(
            "RAR 2.9 DELTA filter channel count is invalid",
        ));
    }

    write_rar29_filtered_archive(entries, options, |entry| {
        unpack29_encode_with_delta_filter_range(entry.data, range.clone(), channels)
            .map_err(Error::from)
    })
}

pub fn write_rar29_itanium_filtered_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_rar29_filtered_archive(entries, options, |entry| {
        unpack29_encode_with_itanium_filter(entry.data).map_err(Error::from)
    })
}

pub fn write_rar29_itanium_range_filtered_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    range: Range<usize>,
) -> Result<Vec<u8>> {
    write_rar29_filtered_archive(entries, options, |entry| {
        unpack29_encode_with_itanium_filter_range(entry.data, range.clone()).map_err(Error::from)
    })
}

pub fn write_rar29_rgb_filtered_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    width: usize,
    pos_r: usize,
) -> Result<Vec<u8>> {
    if width == 0 || !width.is_multiple_of(3) || pos_r > 2 {
        return Err(Error::InvalidHeader(
            "RAR 2.9 RGB filter parameters are invalid",
        ));
    }

    write_rar29_filtered_archive(entries, options, |entry| {
        unpack29_encode_with_rgb_filter(entry.data, width, pos_r).map_err(Error::from)
    })
}

pub fn write_rar29_rgb_range_filtered_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    range: Range<usize>,
    width: usize,
    pos_r: usize,
) -> Result<Vec<u8>> {
    if width == 0 || !width.is_multiple_of(3) || pos_r > 2 {
        return Err(Error::InvalidHeader(
            "RAR 2.9 RGB filter parameters are invalid",
        ));
    }

    write_rar29_filtered_archive(entries, options, |entry| {
        unpack29_encode_with_rgb_filter_range(entry.data, range.clone(), width, pos_r)
            .map_err(Error::from)
    })
}

pub fn write_rar29_audio_filtered_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    channels: usize,
) -> Result<Vec<u8>> {
    if channels == 0 || channels > 32 {
        return Err(Error::InvalidHeader(
            "RAR 2.9 AUDIO filter channel count is invalid",
        ));
    }

    write_rar29_filtered_archive(entries, options, |entry| {
        unpack29_encode_with_audio_filter(entry.data, channels).map_err(Error::from)
    })
}

pub fn write_rar29_audio_range_filtered_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    range: Range<usize>,
    channels: usize,
) -> Result<Vec<u8>> {
    if channels == 0 || channels > 32 {
        return Err(Error::InvalidHeader(
            "RAR 2.9 AUDIO filter channel count is invalid",
        ));
    }

    write_rar29_filtered_archive(entries, options, |entry| {
        unpack29_encode_with_audio_filter_range(entry.data, range.clone(), channels)
            .map_err(Error::from)
    })
}

fn write_rar29_x86_filtered_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    include_e9: bool,
) -> Result<Vec<u8>> {
    write_rar29_filtered_archive(entries, options, |entry| {
        if include_e9 {
            unpack29_encode_with_e8e9_filter(entry.data).map_err(Error::from)
        } else {
            unpack29_encode_with_e8_filter(entry.data).map_err(Error::from)
        }
    })
}

fn write_rar29_x86_range_filtered_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    range: Range<usize>,
    include_e9: bool,
) -> Result<Vec<u8>> {
    write_rar29_filtered_archive(entries, options, |entry| {
        if include_e9 {
            unpack29_encode_with_e8e9_filter_range(entry.data, range.clone()).map_err(Error::from)
        } else {
            unpack29_encode_with_e8_filter_range(entry.data, range.clone()).map_err(Error::from)
        }
    })
}

fn encode_rar29_auto_filtered_member(data: &[u8]) -> Result<Vec<u8>> {
    let mut best = unpack29_encode_literals(data).map_err(Error::from)?;
    let mut candidates = vec![
        unpack29_encode_with_e8_filter(data).map_err(Error::from)?,
        unpack29_encode_with_e8e9_filter(data).map_err(Error::from)?,
        unpack29_encode_with_itanium_filter(data).map_err(Error::from)?,
    ];
    for range in auto_x86_filter_ranges(data, false) {
        candidates.push(unpack29_encode_with_e8_filter_range(data, range).map_err(Error::from)?);
    }
    for range in auto_x86_filter_ranges(data, true) {
        candidates.push(unpack29_encode_with_e8e9_filter_range(data, range).map_err(Error::from)?);
    }
    for channels in 1..=4 {
        candidates.push(unpack29_encode_with_delta_filter(data, channels).map_err(Error::from)?);
        candidates.push(unpack29_encode_with_audio_filter(data, channels).map_err(Error::from)?);
    }
    for width in AUTO_RGB_WIDTHS {
        if data.len() >= width {
            candidates.push(unpack29_encode_with_rgb_filter(data, width, 0).map_err(Error::from)?);
        }
    }

    for packed in candidates {
        if packed.len() < best.len() {
            best = packed;
        }
    }
    Ok(best)
}

fn auto_x86_filter_ranges(data: &[u8], include_e9: bool) -> Vec<Range<usize>> {
    if data.len() <= 5 {
        return Vec::new();
    }

    let cmp_mask = if include_e9 { 0xfe } else { 0xff };
    let mut clusters = Vec::new();
    let mut current: Option<(usize, usize, usize)> = None;
    for (pos, &byte) in data.iter().take(data.len() - 4).enumerate() {
        if byte & cmp_mask != 0xe8 {
            continue;
        }

        match current {
            Some((start, last, count)) if pos - last <= AUTO_X86_CLUSTER_GAP => {
                current = Some((start, pos, count + 1));
            }
            Some(cluster) => {
                clusters.push(cluster);
                current = Some((pos, pos, 1));
            }
            None => current = Some((pos, pos, 1)),
        }
    }
    if let Some(cluster) = current {
        clusters.push(cluster);
    }

    clusters.retain(|&(_, _, count)| count >= 2);
    clusters.sort_by(|a, b| {
        let a_len = a.1 - a.0 + 5;
        let b_len = b.1 - b.0 + 5;
        b.2.cmp(&a.2).then_with(|| a_len.cmp(&b_len))
    });
    clusters.truncate(AUTO_X86_MAX_RANGES);

    let mut ranges = Vec::new();
    for (start, last, _) in clusters {
        let range_start = start.saturating_sub(AUTO_X86_RANGE_PADDING);
        let range_end = (last + 5 + AUTO_X86_RANGE_PADDING).min(data.len());
        let range = range_start..range_end;
        if range.start < range.end && !ranges.contains(&range) {
            ranges.push(range);
        }
    }
    ranges
}

fn write_rar29_filtered_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    mut encode: impl FnMut(&FileEntry<'_>) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    validate_rar29_filtered_writer_options(options)?;
    if options.features.header_encryption {
        validate_header_encrypted_archive_options(options, false, options.features.solid)?;
    }
    let mut out = Vec::new();
    out.extend_from_slice(RAR15_SIGNATURE);
    let main_flags = if options.features.solid { MHD_SOLID } else { 0 }
        | if options.features.header_encryption {
            MHD_PASSWORD
        } else {
            0
        };
    write_main_header(&mut out, main_flags);
    let header_password = if options.features.header_encryption {
        Some(header_encryption_password(
            entries.iter().map(|entry| entry.password),
        )?)
    } else {
        None
    };
    for (index, entry) in entries.iter().enumerate() {
        let packed = encode(entry)?;
        let solid_continuation = options.features.solid && index != 0;
        if let Some(password) = header_password {
            write_header_encrypted_compressed_entry(
                &mut out,
                entry,
                &packed,
                options.target,
                solid_continuation,
                password,
            )?;
        } else {
            write_compressed_entry(&mut out, entry, &packed, options.target, solid_continuation)?;
        }
    }
    Ok(out)
}

fn write_header_encrypted_stored_archive(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
) -> Result<Vec<u8>> {
    validate_header_encrypted_archive_options(options, archive_comment.is_some(), false)?;
    let password = header_encryption_password(entries.iter().map(|entry| entry.password))?;

    let mut out = Vec::new();
    out.extend_from_slice(RAR15_SIGNATURE);
    write_main_header(&mut out, MHD_PASSWORD);
    for entry in entries {
        write_header_encrypted_stored_entry(&mut out, entry, options.target, password)?;
    }
    Ok(out)
}

fn write_header_encrypted_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
) -> Result<Vec<u8>> {
    validate_header_encrypted_archive_options(
        options,
        archive_comment.is_some(),
        options.features.solid,
    )?;
    let password = header_encryption_password(entries.iter().map(|entry| entry.password))?;

    let mut out = Vec::new();
    out.extend_from_slice(RAR15_SIGNATURE);
    let main_flags = MHD_PASSWORD | if options.features.solid { MHD_SOLID } else { 0 };
    write_main_header(&mut out, main_flags);
    let mut solid_encoder = SolidEncoder::for_target(options.target, options.features.solid);
    for (index, entry) in entries.iter().enumerate() {
        let packed = encode_compressed_payload(entry.data, options.target, solid_encoder.as_mut())?;
        write_header_encrypted_compressed_entry(
            &mut out,
            entry,
            &packed,
            options.target,
            options.features.solid && index != 0,
            password,
        )?;
    }
    Ok(out)
}

pub fn write_stored_volumes(
    entry: StoredEntry<'_>,
    options: WriterOptions,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    validate_stored_writer_options(options, false, false)?;
    validate_volume_writer_inputs(
        entry.name,
        entry.data,
        entry.password,
        entry.file_comment,
        options,
    )?;
    if options.features.header_encryption {
        return write_header_encrypted_split_volumes(SplitVolumeRecord {
            name: entry.name,
            unpacked: entry.data,
            packed: entry.data,
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            target: options.target,
            method: 0x30,
            base_flags: writer_file_flags(entry.password, None, false),
            main_flags: 0,
            password: entry.password,
            max_packed_per_volume,
        });
    }

    write_split_volumes(SplitVolumeRecord {
        name: entry.name,
        unpacked: entry.data,
        packed: entry.data,
        file_time: entry.file_time,
        file_attr: entry.file_attr,
        host_os: entry.host_os,
        target: options.target,
        method: 0x30,
        base_flags: writer_file_flags(entry.password, None, false),
        main_flags: 0,
        password: entry.password,
        max_packed_per_volume,
    })
}

pub fn write_compressed_volumes(
    entry: FileEntry<'_>,
    options: WriterOptions,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    validate_compressed_writer_options(options, false, false)?;
    validate_volume_writer_inputs(
        entry.name,
        entry.data,
        entry.password,
        entry.file_comment,
        options,
    )?;

    let packed = encode_compressed_payload(entry.data, options.target, None)?;
    if options.features.header_encryption {
        return write_header_encrypted_split_volumes(SplitVolumeRecord {
            name: entry.name,
            unpacked: entry.data,
            packed: &packed,
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            target: options.target,
            method: 0x33,
            base_flags: writer_file_flags(entry.password, None, false),
            main_flags: if options.features.solid { MHD_SOLID } else { 0 },
            password: entry.password,
            max_packed_per_volume,
        });
    }

    write_split_volumes(SplitVolumeRecord {
        name: entry.name,
        unpacked: entry.data,
        packed: &packed,
        file_time: entry.file_time,
        file_attr: entry.file_attr,
        host_os: entry.host_os,
        target: options.target,
        method: 0x33,
        base_flags: writer_file_flags(entry.password, None, false),
        main_flags: if options.features.solid { MHD_SOLID } else { 0 },
        password: entry.password,
        max_packed_per_volume,
    })
}

fn validate_stored_writer_options(
    options: WriterOptions,
    has_archive_comment: bool,
    has_file_comment: bool,
) -> Result<()> {
    if !matches!(
        options.target,
        ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = FeatureSet::store_only();
    allowed.file_encryption =
        writer_supports_file_encryption(options.target) && options.features.file_encryption;
    allowed.header_encryption =
        writer_supports_header_encryption(options.target) && options.features.header_encryption;
    allowed.archive_comment = matches!(
        options.target,
        ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    ) && has_archive_comment;
    allowed.file_comment = matches!(
        options.target,
        ArchiveVersion::Rar15 | ArchiveVersion::Rar20 | ArchiveVersion::Rar29
    ) && has_file_comment;
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 1.5 writer feature",
        });
    }
    Ok(())
}

fn validate_compressed_writer_options(
    options: WriterOptions,
    has_archive_comment: bool,
    has_file_comment: bool,
) -> Result<()> {
    if !matches!(
        options.target,
        ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = FeatureSet::store_only();
    allowed.solid = matches!(
        options.target,
        ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    ) && options.features.solid;
    allowed.file_encryption =
        writer_supports_file_encryption(options.target) && options.features.file_encryption;
    allowed.header_encryption =
        writer_supports_header_encryption(options.target) && options.features.header_encryption;
    allowed.archive_comment = matches!(
        options.target,
        ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    ) && has_archive_comment;
    allowed.file_comment = matches!(
        options.target,
        ArchiveVersion::Rar15 | ArchiveVersion::Rar20 | ArchiveVersion::Rar29
    ) && has_file_comment;
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 1.5 writer feature",
        });
    }
    Ok(())
}

fn validate_rar29_filtered_writer_options(options: WriterOptions) -> Result<()> {
    if !matches!(
        options.target,
        ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = FeatureSet::store_only();
    allowed.solid = options.features.solid;
    allowed.file_encryption =
        writer_supports_file_encryption(options.target) && options.features.file_encryption;
    allowed.header_encryption =
        writer_supports_header_encryption(options.target) && options.features.header_encryption;
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 2.9 RARVM-filtered compressed writer feature",
        });
    }
    Ok(())
}

fn validate_header_encrypted_archive_options(
    options: WriterOptions,
    has_archive_comment: bool,
    _solid: bool,
) -> Result<()> {
    if has_archive_comment {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 3.x header-encrypted archive comments",
        });
    }
    if !options.features.file_encryption {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 3.x header encryption without file encryption",
        });
    }
    Ok(())
}

enum SolidEncoder {
    Rar15(Box<Unpack15Encoder>),
    Rar20(Unpack20Encoder),
    Rar29(Unpack29Encoder),
}

impl SolidEncoder {
    fn for_target(target: ArchiveVersion, solid: bool) -> Option<Self> {
        if !solid {
            return None;
        }
        match target {
            ArchiveVersion::Rar15 => Some(Self::Rar15(Box::new(Unpack15Encoder::new()))),
            ArchiveVersion::Rar20 => Some(Self::Rar20(Unpack20Encoder::new())),
            ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => {
                Some(Self::Rar29(Unpack29Encoder::new()))
            }
            _ => None,
        }
    }
}

fn encode_compressed_payload(
    data: &[u8],
    target: ArchiveVersion,
    solid_encoder: Option<&mut SolidEncoder>,
) -> Result<Vec<u8>> {
    match (target, solid_encoder) {
        (ArchiveVersion::Rar15, Some(SolidEncoder::Rar15(encoder))) => {
            encoder.encode_member(data).map_err(Error::from)
        }
        (ArchiveVersion::Rar15, None) => unpack15_encode(data).map_err(Error::from),
        (ArchiveVersion::Rar20, None) => unpack20_encode_literals(data).map_err(Error::from),
        (ArchiveVersion::Rar20, Some(SolidEncoder::Rar20(encoder))) => {
            encoder.encode_member(data).map_err(Error::from)
        }
        (ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40, None) => {
            unpack29_encode_literals(data).map_err(Error::from)
        }
        (
            ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40,
            Some(SolidEncoder::Rar29(encoder)),
        ) => encoder.encode_member(data).map_err(Error::from),
        _ => Err(Error::UnsupportedVersion(target)),
    }
}

fn validate_volume_writer_inputs(
    name: &[u8],
    data: &[u8],
    password: Option<&[u8]>,
    file_comment: Option<&[u8]>,
    options: WriterOptions,
) -> Result<()> {
    validate_file_entry(name, data)?;
    if password.is_some()
        && !matches!(
            options.target,
            ArchiveVersion::Rar15
                | ArchiveVersion::Rar20
                | ArchiveVersion::Rar29
                | ArchiveVersion::Rar30
                | ArchiveVersion::Rar40
        )
    {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 2.9 encrypted volume writer",
        });
    }
    if file_comment.is_some() {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "volume_file_comment",
        });
    }
    Ok(())
}

fn writer_file_flags(
    password: Option<&[u8]>,
    file_comment: Option<&[u8]>,
    solid_continuation: bool,
) -> u16 {
    let mut flags = 0;
    if password.is_some() {
        flags |= FHD_PASSWORD;
    }
    if file_comment.is_some() {
        flags |= FHD_COMMENT;
    }
    if solid_continuation {
        flags |= FHD_SOLID;
    }
    flags
}

fn encode_file_comment(comment: Option<&[u8]>) -> Result<Vec<u8>> {
    let Some(comment) = comment else {
        return Ok(Vec::new());
    };
    if comment.len() > u16::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.5 file comment is longer than 65535 bytes",
        ));
    }
    let mut out = Vec::with_capacity(2 + comment.len());
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(comment);
    Ok(out)
}

fn encrypt_split_packed_data(
    data: &mut Vec<u8>,
    target: ArchiveVersion,
    password: &[u8],
) -> Result<Option<[u8; 8]>> {
    match target {
        ArchiveVersion::Rar15 => {
            Rar15Cipher::new(password).crypt_in_place(data);
            Ok(None)
        }
        ArchiveVersion::Rar20 => {
            let padded_len = align16(data.len())?;
            data.resize(padded_len, 0);
            Rar20Cipher::new(password).encrypt_in_place(data);
            Ok(None)
        }
        ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => {
            let salt = random_rar30_salt()?;
            let padded_len = align16(data.len())?;
            data.resize(padded_len, 0);
            Rar30Cipher::new(password, Some(salt)).encrypt_in_place(data);
            Ok(Some(salt))
        }
        _ => Err(Error::UnsupportedVersion(target)),
    }
}

fn writer_supports_file_encryption(target: ArchiveVersion) -> bool {
    matches!(
        target,
        ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    )
}

fn writer_supports_header_encryption(target: ArchiveVersion) -> bool {
    matches!(target, ArchiveVersion::Rar30 | ArchiveVersion::Rar40)
}

fn header_encryption_password<'a>(
    mut passwords: impl Iterator<Item = Option<&'a [u8]>>,
) -> Result<&'a [u8]> {
    let first = passwords.next().flatten().ok_or(Error::NeedPassword)?;
    for password in passwords {
        if password != Some(first) {
            return Err(Error::InvalidHeader(
                "RAR 3.x header-encrypted writer needs one shared password",
            ));
        }
    }
    Ok(first)
}

fn encrypt_packed_data_for_writer(
    data: &mut Vec<u8>,
    target: ArchiveVersion,
    password: Option<&[u8]>,
) -> Result<Option<[u8; 8]>> {
    let Some(password) = password else {
        return Ok(None);
    };
    validate_writer_password(target, Some(password))?;
    match target {
        ArchiveVersion::Rar15 => {
            Rar15Cipher::new(password).crypt_in_place(data);
            Ok(None)
        }
        ArchiveVersion::Rar20 => {
            let padded_len = align16(data.len())?;
            data.resize(padded_len, 0);
            Rar20Cipher::new(password).encrypt_in_place(data);
            Ok(None)
        }
        ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => {
            let salt = random_rar30_salt()?;
            let padded_len =
                data.len()
                    .checked_add(15)
                    .map(|len| len & !15)
                    .ok_or(Error::InvalidHeader(
                        "RAR 3.x encrypted data size overflows",
                    ))?;
            data.resize(padded_len, 0);
            Rar30Cipher::new(password, Some(salt)).encrypt_in_place(data);
            Ok(Some(salt))
        }
        _ => Err(Error::UnsupportedFeature {
            version: target,
            feature: "RAR writer file encryption",
        }),
    }
}

fn random_rar30_salt() -> Result<[u8; 8]> {
    let mut salt = [0; 8];
    getrandom::getrandom(&mut salt)
        .map_err(|_| Error::InvalidHeader("RAR 3.x writer could not generate encryption salt"))?;
    Ok(salt)
}

fn write_main_header(out: &mut Vec<u8>, flags: u16) {
    let start = out.len();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.push(MAIN_HEAD);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&13u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    write_header_crc(out, start);
}

fn write_comment_header(out: &mut Vec<u8>, comment: Option<&[u8]>) -> Result<()> {
    let Some(comment) = comment else {
        return Ok(());
    };
    let unp_size = u16::try_from(comment.len())
        .map_err(|_| Error::InvalidHeader("RAR 1.5 archive comment is too long"))?;
    let head_size = 13usize
        .checked_add(comment.len())
        .ok_or(Error::InvalidHeader(
            "RAR 1.5 comment header size overflows",
        ))?;
    let head_size = u16::try_from(head_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 comment header size overflows"))?;

    let start = out.len();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.push(COMM_HEAD);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&head_size.to_le_bytes());
    out.extend_from_slice(&unp_size.to_le_bytes());
    out.push(15);
    out.push(0x30);
    out.extend_from_slice(&((crc32(comment) & 0xffff) as u16).to_le_bytes());
    out.extend_from_slice(comment);
    write_comment_header_crc(out, start);
    Ok(())
}

fn uses_old_style_archive_comment(target: ArchiveVersion) -> bool {
    matches!(
        target,
        ArchiveVersion::Rar15 | ArchiveVersion::Rar20 | ArchiveVersion::Rar29
    )
}

fn write_archive_comment(
    out: &mut Vec<u8>,
    comment: Option<&[u8]>,
    target: ArchiveVersion,
) -> Result<()> {
    if uses_old_style_archive_comment(target) {
        return write_comment_header(out, comment);
    }
    match target {
        ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => write_newsub_archive_comment(out, comment),
        _ => Err(Error::UnsupportedVersion(target)),
    }
}

fn write_newsub_archive_comment(out: &mut Vec<u8>, comment: Option<&[u8]>) -> Result<()> {
    let Some(comment) = comment else {
        return Ok(());
    };
    let packed = unpack29_encode_literals(comment)?;
    write_file_header_and_data(
        out,
        FileRecord {
            head_type: NEWSUB_HEAD,
            name: b"CMT",
            unpacked_size: comment.len(),
            file_crc: crc32(comment),
            packed: &packed,
            file_time: 0,
            file_attr: 0,
            host_os: 3,
            target: ArchiveVersion::Rar30,
            method: 0x33,
            flags: 0,
            salt: None,
            extra: &[],
        },
    )
}

fn write_stored_entry(
    out: &mut Vec<u8>,
    entry: &StoredEntry<'_>,
    target: ArchiveVersion,
) -> Result<()> {
    validate_stored_entry(entry)?;
    validate_writer_password(target, entry.password)?;
    let mut packed = entry.data.to_vec();
    let salt = encrypt_packed_data_for_writer(&mut packed, target, entry.password)?;
    let mut flags = writer_file_flags(entry.password, entry.file_comment, false);
    if salt.is_some() {
        flags |= FHD_SALT;
    }
    let file_comment = encode_file_comment(entry.file_comment)?;
    write_file_header_and_data(
        out,
        FileRecord {
            head_type: FILE_HEAD,
            name: entry.name,
            unpacked_size: entry.data.len(),
            file_crc: crc32(entry.data),
            packed: &packed,
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            target,
            method: 0x30,
            flags,
            salt,
            extra: &file_comment,
        },
    )
}

fn write_compressed_entry(
    out: &mut Vec<u8>,
    entry: &FileEntry<'_>,
    packed: &[u8],
    target: ArchiveVersion,
    solid_continuation: bool,
) -> Result<()> {
    validate_file_entry(entry.name, entry.data)?;
    validate_writer_password(target, entry.password)?;
    let mut packed = packed.to_vec();
    let salt = encrypt_packed_data_for_writer(&mut packed, target, entry.password)?;
    let mut flags = writer_file_flags(entry.password, entry.file_comment, solid_continuation);
    if salt.is_some() {
        flags |= FHD_SALT;
    }
    let file_comment = encode_file_comment(entry.file_comment)?;
    write_file_header_and_data(
        out,
        FileRecord {
            head_type: FILE_HEAD,
            name: entry.name,
            unpacked_size: entry.data.len(),
            file_crc: crc32(entry.data),
            packed: &packed,
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            target,
            method: 0x33,
            flags,
            salt,
            extra: &file_comment,
        },
    )
}

fn write_header_encrypted_stored_entry(
    out: &mut Vec<u8>,
    entry: &StoredEntry<'_>,
    target: ArchiveVersion,
    header_password: &[u8],
) -> Result<()> {
    validate_stored_entry(entry)?;
    validate_writer_password(target, entry.password)?;
    let mut packed = entry.data.to_vec();
    let salt = encrypt_packed_data_for_writer(&mut packed, target, entry.password)?;
    let mut flags = writer_file_flags(entry.password, entry.file_comment, false);
    if salt.is_some() {
        flags |= FHD_SALT;
    }
    let file_comment = encode_file_comment(entry.file_comment)?;
    let mut header = Vec::new();
    write_file_header(
        &mut header,
        &FileRecord {
            head_type: FILE_HEAD,
            name: entry.name,
            unpacked_size: entry.data.len(),
            file_crc: crc32(entry.data),
            packed: &packed,
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            target,
            method: 0x30,
            flags,
            salt,
            extra: &file_comment,
        },
    )?;
    write_encrypted_header_and_data(out, &header, &packed, header_password)
}

fn write_header_encrypted_compressed_entry(
    out: &mut Vec<u8>,
    entry: &FileEntry<'_>,
    packed: &[u8],
    target: ArchiveVersion,
    solid_continuation: bool,
    header_password: &[u8],
) -> Result<()> {
    validate_file_entry(entry.name, entry.data)?;
    validate_writer_password(target, entry.password)?;
    let mut packed = packed.to_vec();
    let salt = encrypt_packed_data_for_writer(&mut packed, target, entry.password)?;
    let mut flags = writer_file_flags(entry.password, entry.file_comment, solid_continuation);
    if salt.is_some() {
        flags |= FHD_SALT;
    }
    let file_comment = encode_file_comment(entry.file_comment)?;
    let mut header = Vec::new();
    write_file_header(
        &mut header,
        &FileRecord {
            head_type: FILE_HEAD,
            name: entry.name,
            unpacked_size: entry.data.len(),
            file_crc: crc32(entry.data),
            packed: &packed,
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            target,
            method: 0x33,
            flags,
            salt,
            extra: &file_comment,
        },
    )?;
    write_encrypted_header_and_data(out, &header, &packed, header_password)
}

fn write_encrypted_header_and_data(
    out: &mut Vec<u8>,
    header: &[u8],
    data: &[u8],
    password: &[u8],
) -> Result<()> {
    let salt = random_rar30_salt()?;
    let encrypted_size = align16(header.len())?;
    let mut encrypted_header = Vec::with_capacity(encrypted_size);
    encrypted_header.extend_from_slice(header);
    encrypted_header.resize(encrypted_size, 0);
    Rar30Cipher::new(password, Some(salt)).encrypt_in_place(&mut encrypted_header);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&encrypted_header);
    out.extend_from_slice(data);
    Ok(())
}

fn validate_writer_password(target: ArchiveVersion, password: Option<&[u8]>) -> Result<()> {
    if password.is_some() && !writer_supports_file_encryption(target) {
        return Err(Error::UnsupportedFeature {
            version: target,
            feature: "RAR writer file encryption",
        });
    }
    Ok(())
}

fn validate_stored_entry(entry: &StoredEntry<'_>) -> Result<()> {
    if entry.name.is_empty() {
        return Err(Error::InvalidHeader("RAR 1.5 file name is empty"));
    }
    if entry.name.len() > u16::MAX as usize {
        return Err(Error::InvalidHeader("RAR 1.5 file name is too long"));
    }
    if entry.data.len() > u32::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.5 store-only writer does not support large files",
        ));
    }
    Ok(())
}

fn validate_file_entry(name: &[u8], data: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidHeader("RAR 1.5 file name is empty"));
    }
    if name.len() > u16::MAX as usize {
        return Err(Error::InvalidHeader("RAR 1.5 file name is too long"));
    }
    if data.len() > u32::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.5 writer does not support large files",
        ));
    }
    Ok(())
}

struct FileRecord<'a> {
    head_type: u8,
    name: &'a [u8],
    unpacked_size: usize,
    file_crc: u32,
    packed: &'a [u8],
    file_time: u32,
    file_attr: u32,
    host_os: u8,
    target: ArchiveVersion,
    method: u8,
    flags: u16,
    salt: Option<[u8; 8]>,
    extra: &'a [u8],
}

fn write_file_header_and_data(out: &mut Vec<u8>, record: FileRecord<'_>) -> Result<()> {
    write_file_header(out, &record)?;
    out.extend_from_slice(record.packed);
    Ok(())
}

fn write_file_header(out: &mut Vec<u8>, record: &FileRecord<'_>) -> Result<()> {
    let start = out.len();
    let packed_size = u32::try_from(record.packed.len())
        .map_err(|_| Error::InvalidHeader("RAR 1.5 packed size overflows u32"))?;
    let unpacked_size = u32::try_from(record.unpacked_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 unpacked size overflows u32"))?;
    let head_size = 32usize
        .checked_add(record.name.len())
        .and_then(|size| size.checked_add(if record.salt.is_some() { 8 } else { 0 }))
        .and_then(|size| size.checked_add(record.extra.len()))
        .ok_or(Error::InvalidHeader("RAR 1.5 file header size overflows"))?;
    let head_size = u16::try_from(head_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 file header size overflows"))?;
    let unp_ver = match record.target {
        ArchiveVersion::Rar15 => 15,
        ArchiveVersion::Rar20 => 20,
        ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => 29,
        _ => return Err(Error::UnsupportedVersion(record.target)),
    };
    out.extend_from_slice(&0u16.to_le_bytes());
    out.push(record.head_type);
    out.extend_from_slice(&(LONG_BLOCK | record.flags).to_le_bytes());
    out.extend_from_slice(&head_size.to_le_bytes());
    out.extend_from_slice(&packed_size.to_le_bytes());
    out.extend_from_slice(&unpacked_size.to_le_bytes());
    out.push(record.host_os);
    out.extend_from_slice(&record.file_crc.to_le_bytes());
    out.extend_from_slice(&record.file_time.to_le_bytes());
    out.push(unp_ver);
    out.push(record.method);
    out.extend_from_slice(&(record.name.len() as u16).to_le_bytes());
    out.extend_from_slice(&record.file_attr.to_le_bytes());
    out.extend_from_slice(record.name);
    if let Some(salt) = record.salt {
        out.extend_from_slice(&salt);
    }
    out.extend_from_slice(record.extra);
    write_file_header_crc(out, start, record.name.len(), record.flags);
    Ok(())
}

struct SplitVolumeRecord<'a> {
    name: &'a [u8],
    unpacked: &'a [u8],
    packed: &'a [u8],
    file_time: u32,
    file_attr: u32,
    host_os: u8,
    target: ArchiveVersion,
    method: u8,
    base_flags: u16,
    main_flags: u16,
    password: Option<&'a [u8]>,
    max_packed_per_volume: usize,
}

fn write_split_volumes(entry: SplitVolumeRecord<'_>) -> Result<Vec<Vec<u8>>> {
    if entry.max_packed_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume payload size must be non-zero",
        ));
    }
    if entry.packed.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume writer needs a non-empty packed payload",
        ));
    }

    let mut packed = entry.packed.to_vec();
    let split_salt = if let Some(password) = entry.password {
        encrypt_split_packed_data(&mut packed, entry.target, password)?
    } else {
        None
    };
    let base_flags = entry.base_flags | if split_salt.is_some() { FHD_SALT } else { 0 };

    let chunks: Vec<&[u8]> = packed.chunks(entry.max_packed_per_volume).collect();
    if chunks.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume writer needs at least two volumes",
        ));
    }

    let mut volumes = Vec::with_capacity(chunks.len());
    let unpacked_crc = crc32(entry.unpacked);
    for (index, chunk) in chunks.iter().enumerate() {
        let split_before = index > 0;
        let split_after = index + 1 < chunks.len();
        let mut file_flags = base_flags;
        if split_before {
            file_flags |= FHD_SPLIT_BEFORE;
        }
        if split_after {
            file_flags |= FHD_SPLIT_AFTER;
        }

        let mut main_flags = MHD_VOLUME | entry.main_flags;
        if index == 0 {
            main_flags |= MHD_FIRSTVOLUME;
        }

        let mut out = Vec::new();
        out.extend_from_slice(RAR15_SIGNATURE);
        write_main_header(&mut out, main_flags);
        write_file_header_and_data(
            &mut out,
            FileRecord {
                head_type: FILE_HEAD,
                name: entry.name,
                unpacked_size: entry.unpacked.len(),
                file_crc: if split_after {
                    crc32(chunk)
                } else {
                    unpacked_crc
                },
                packed: chunk,
                file_time: entry.file_time,
                file_attr: entry.file_attr,
                host_os: entry.host_os,
                target: entry.target,
                method: entry.method,
                flags: file_flags,
                salt: split_salt,
                extra: &[],
            },
        )?;
        volumes.push(out);
    }

    Ok(volumes)
}

fn write_header_encrypted_split_volumes(entry: SplitVolumeRecord<'_>) -> Result<Vec<Vec<u8>>> {
    validate_header_encrypted_archive_options(
        WriterOptions {
            target: entry.target,
            features: {
                let mut features = FeatureSet::store_only();
                features.file_encryption = entry.password.is_some();
                features.header_encryption = true;
                features.solid = entry.main_flags & MHD_SOLID != 0;
                features
            },
        },
        false,
        entry.main_flags & MHD_SOLID != 0,
    )?;
    let password = entry.password.ok_or(Error::NeedPassword)?;
    if entry.max_packed_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume payload size must be non-zero",
        ));
    }
    if entry.packed.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume writer needs a non-empty packed payload",
        ));
    }

    let mut packed = entry.packed.to_vec();
    let split_salt = encrypt_split_packed_data(&mut packed, entry.target, password)?;
    let base_flags = entry.base_flags | FHD_SALT;
    let chunks: Vec<&[u8]> = packed.chunks(entry.max_packed_per_volume).collect();
    if chunks.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume writer needs at least two volumes",
        ));
    }

    let mut volumes = Vec::with_capacity(chunks.len());
    let unpacked_crc = crc32(entry.unpacked);
    for (index, chunk) in chunks.iter().enumerate() {
        let split_before = index > 0;
        let split_after = index + 1 < chunks.len();
        let mut file_flags = base_flags;
        if split_before {
            file_flags |= FHD_SPLIT_BEFORE;
        }
        if split_after {
            file_flags |= FHD_SPLIT_AFTER;
        }

        let mut main_flags = MHD_VOLUME | MHD_PASSWORD | entry.main_flags;
        if index == 0 {
            main_flags |= MHD_FIRSTVOLUME;
        }

        let mut out = Vec::new();
        out.extend_from_slice(RAR15_SIGNATURE);
        write_main_header(&mut out, main_flags);
        let mut header = Vec::new();
        write_file_header(
            &mut header,
            &FileRecord {
                head_type: FILE_HEAD,
                name: entry.name,
                unpacked_size: entry.unpacked.len(),
                file_crc: if split_after {
                    crc32(chunk)
                } else {
                    unpacked_crc
                },
                packed: chunk,
                file_time: entry.file_time,
                file_attr: entry.file_attr,
                host_os: entry.host_os,
                target: entry.target,
                method: entry.method,
                flags: file_flags,
                salt: split_salt,
                extra: &[],
            },
        )?;
        write_encrypted_header_and_data(&mut out, &header, chunk, password)?;
        volumes.push(out);
    }

    Ok(volumes)
}

fn write_header_crc(out: &mut [u8], start: usize) {
    let crc = (crc32(&out[start + 2..]) & 0xffff) as u16;
    out[start..start + 2].copy_from_slice(&crc.to_le_bytes());
}

fn write_file_header_crc(out: &mut [u8], start: usize, name_len: usize, flags: u16) {
    let end = if flags & FHD_COMMENT != 0 {
        start + 32 + name_len
    } else {
        out.len()
    };
    let crc = (crc32(&out[start + 2..end]) & 0xffff) as u16;
    out[start..start + 2].copy_from_slice(&crc.to_le_bytes());
}

fn write_comment_header_crc(out: &mut [u8], start: usize) {
    let end = start + 13;
    let crc = (crc32(&out[start + 2..end]) & 0xffff) as u16;
    out[start..start + 2].copy_from_slice(&crc.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::auto_x86_filter_ranges;

    #[test]
    fn auto_x86_filter_ranges_select_dense_opcode_clusters() {
        let mut data = vec![0x41; 20_000];
        for pos in [1024, 1050, 1090, 1130] {
            data[pos] = 0xe8;
        }
        for pos in [12_000, 12_040, 12_080] {
            data[pos] = 0xe9;
        }

        let e8_ranges = auto_x86_filter_ranges(&data, false);
        assert_eq!(e8_ranges.len(), 1);
        assert!(e8_ranges[0].contains(&1024));
        assert!(e8_ranges[0].contains(&(1130 + 4)));
        assert!(!e8_ranges[0].contains(&12_000));

        let e8e9_ranges = auto_x86_filter_ranges(&data, true);
        assert_eq!(e8e9_ranges.len(), 2);
        assert!(e8e9_ranges.iter().any(|range| range.contains(&1024)));
        assert!(e8e9_ranges.iter().any(|range| range.contains(&12_000)));
    }
}
