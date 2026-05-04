use super::*;
use rars_codec::rar50::{
    encode_lz_member, encode_lz_member_with_arm_filter, encode_lz_member_with_delta_filter,
    encode_lz_member_with_e8_filter, Unpack50Encoder,
};
use rars_crypto::rar50::{Rar50Cipher, Rar50Keys};
use rars_recovery::rar5::build_structural_inline_recovery_data;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterOptions {
    pub target: crate::ArchiveVersion,
    pub features: crate::FeatureSet,
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            target: crate::ArchiveVersion::Rar50,
            features: crate::FeatureSet::store_only(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub mtime: Option<u32>,
    pub attributes: u64,
    pub host_os: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub mtime: Option<u32>,
    pub attributes: u64,
    pub host_os: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredServiceEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredEntryWithServices<'a> {
    pub entry: StoredEntry<'a>,
    pub services: &'a [StoredServiceEntry<'a>],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedStoredServiceEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub password: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedStoredEntryWithServices<'a> {
    pub entry: EncryptedStoredEntry<'a>,
    pub services: &'a [EncryptedStoredServiceEntry<'a>],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveMetadataEntry<'a> {
    pub name: Option<&'a [u8]>,
    pub creation_time: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedStoredEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub mtime: Option<u32>,
    pub attributes: u64,
    pub host_os: u64,
    pub password: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedCompressedEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub mtime: Option<u32>,
    pub attributes: u64,
    pub host_os: u64,
    pub password: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedArchiveCommentEntry<'a> {
    pub data: &'a [u8],
    pub password: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterPolicy {
    None,
    AutoSize,
    Explicit(FilterKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterKind {
    Delta { channels: usize },
    E8,
    E8E9,
    Arm,
}

pub fn write_stored_archive(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_stored_archive_with_comment(entries, options, None)
}

pub fn write_compressed_archive(
    entries: &[CompressedEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_compressed_archive_with_comment_and_metadata(entries, options, None, None)
}

pub fn write_compressed_archive_with_metadata(
    entries: &[CompressedEntry<'_>],
    options: WriterOptions,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
) -> Result<Vec<u8>> {
    write_compressed_archive_with_comment_and_metadata(entries, options, None, archive_metadata)
}

pub fn write_compressed_archive_with_comment_and_metadata(
    entries: &[CompressedEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
) -> Result<Vec<u8>> {
    validate_compressed_options(options)?;

    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    let mut main_extra = Vec::new();
    if let Some(archive_metadata) = archive_metadata {
        write_locator_record(&mut main_extra, Some(0), None);
        main_extra.extend_from_slice(&archive_metadata_record(archive_metadata)?);
    }
    let main_flags = if options.features.solid {
        MHFL_SOLID
    } else {
        0
    };
    write_main_header(&mut out, main_flags, None, &main_extra)?;
    if let Some(comment) = archive_comment {
        write_stored_service(&mut out, b"CMT", comment)?;
    }
    let algorithm_version = match options.target {
        crate::ArchiveVersion::Rar50 => 0,
        crate::ArchiveVersion::Rar70 => 1,
        _ => return Err(Error::UnsupportedVersion(options.target)),
    };
    let mut solid_encoder = options.features.solid.then(Unpack50Encoder::new);
    for (index, entry) in entries.iter().enumerate() {
        validate_compressed_entry(entry)?;
        let packed = if let Some(encoder) = solid_encoder.as_mut() {
            encoder
                .encode_member(entry.data, algorithm_version)
                .map_err(Error::from)?
        } else {
            encode_lz_member(entry.data, algorithm_version).map_err(Error::from)?
        };
        write_compressed_entry_payload(
            &mut out,
            entry,
            &packed,
            algorithm_version,
            options.features.solid && index != 0,
        )?;
    }
    write_block(&mut out, HEAD_END, 0, None, &[], &[], &[])?;
    Ok(out)
}

pub fn write_compressed_archive_with_recovery(
    entries: &[CompressedEntry<'_>],
    options: WriterOptions,
    recovery_percent: u64,
) -> Result<Vec<u8>> {
    validate_compressed_recovery_options(options)?;
    validate_recovery_percent(recovery_percent)?;

    let mut recovery_offset = 0;
    for _ in 0..4 {
        let (out, next_recovery_offset) = write_compressed_archive_recovery_pass(
            entries,
            options,
            recovery_percent,
            recovery_offset,
        )?;
        if next_recovery_offset == recovery_offset {
            return Ok(out);
        }
        recovery_offset = next_recovery_offset;
    }
    write_compressed_archive_recovery_pass(entries, options, recovery_percent, recovery_offset)
        .map(|(out, _)| out)
}

fn write_compressed_archive_recovery_pass(
    entries: &[CompressedEntry<'_>],
    options: WriterOptions,
    recovery_percent: u64,
    recovery_offset: u64,
) -> Result<(Vec<u8>, u64)> {
    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    let mut main_extra = Vec::new();
    write_locator_record(&mut main_extra, None, Some(recovery_offset));
    let main_flags = MHFL_RECOVERY
        | if options.features.solid {
            MHFL_SOLID
        } else {
            0
        };
    write_main_header(&mut out, main_flags, None, &main_extra)?;
    let algorithm_version = match options.target {
        crate::ArchiveVersion::Rar50 => 0,
        crate::ArchiveVersion::Rar70 => 1,
        _ => return Err(Error::UnsupportedVersion(options.target)),
    };
    let mut solid_encoder = options.features.solid.then(Unpack50Encoder::new);
    for (index, entry) in entries.iter().enumerate() {
        validate_compressed_entry(entry)?;
        let packed = if let Some(encoder) = solid_encoder.as_mut() {
            encoder
                .encode_member(entry.data, algorithm_version)
                .map_err(Error::from)?
        } else {
            encode_lz_member(entry.data, algorithm_version).map_err(Error::from)?
        };
        write_compressed_entry_payload(
            &mut out,
            entry,
            &packed,
            algorithm_version,
            options.features.solid && index != 0,
        )?;
    }
    let rr_pos = out.len();
    write_recovery_service(&mut out, recovery_percent)?;
    write_block(&mut out, HEAD_END, 0, None, &[], &[], &[])?;
    Ok((out, (rr_pos - RAR50_SIGNATURE.len()) as u64))
}

pub fn write_compressed_archive_with_filter_policy(
    entries: &[CompressedEntry<'_>],
    options: WriterOptions,
    policy: FilterPolicy,
) -> Result<Vec<u8>> {
    if policy == FilterPolicy::None {
        return write_compressed_archive(entries, options);
    }
    validate_compressed_options(options)?;
    if options.features.solid {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 solid filtered compressed writer",
        });
    }

    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    write_main_header(&mut out, 0, None, &[])?;
    let algorithm_version = match options.target {
        crate::ArchiveVersion::Rar50 => 0,
        crate::ArchiveVersion::Rar70 => 1,
        _ => return Err(Error::UnsupportedVersion(options.target)),
    };
    for entry in entries {
        validate_compressed_entry(entry)?;
        let packed = encode_member_with_filter_policy(entry.data, algorithm_version, policy)?;
        write_compressed_entry_payload(&mut out, entry, &packed, algorithm_version, false)?;
    }
    write_block(&mut out, HEAD_END, 0, None, &[], &[], &[])?;
    Ok(out)
}

pub fn write_delta_filtered_compressed_archive(
    entries: &[CompressedEntry<'_>],
    options: WriterOptions,
    channels: usize,
) -> Result<Vec<u8>> {
    write_compressed_archive_with_filter_policy(
        entries,
        options,
        FilterPolicy::Explicit(FilterKind::Delta { channels }),
    )
}

pub fn write_e8_filtered_compressed_archive(
    entries: &[CompressedEntry<'_>],
    options: WriterOptions,
    include_e9: bool,
) -> Result<Vec<u8>> {
    let filter = if include_e9 {
        FilterKind::E8E9
    } else {
        FilterKind::E8
    };
    write_compressed_archive_with_filter_policy(entries, options, FilterPolicy::Explicit(filter))
}

pub fn write_arm_filtered_compressed_archive(
    entries: &[CompressedEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_compressed_archive_with_filter_policy(
        entries,
        options,
        FilterPolicy::Explicit(FilterKind::Arm),
    )
}

pub fn write_stored_archive_with_comment(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
) -> Result<Vec<u8>> {
    write_stored_archive_with_comment_and_metadata(entries, options, archive_comment, None)
}

pub fn write_stored_archive_with_comment_and_metadata(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
) -> Result<Vec<u8>> {
    validate_options(options)?;
    if options.features.quick_open {
        return write_stored_archive_with_quick_open(entries, archive_comment, archive_metadata);
    }

    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    let mut main_extra = Vec::new();
    if let Some(archive_metadata) = archive_metadata {
        write_locator_record(&mut main_extra, Some(0), None);
        main_extra.extend_from_slice(&archive_metadata_record(archive_metadata)?);
    }
    write_main_header(&mut out, 0, None, &main_extra)?;
    if let Some(comment) = archive_comment {
        write_stored_service(&mut out, b"CMT", comment)?;
    }
    for entry in entries {
        write_stored_entry(&mut out, entry)?;
    }
    write_block(&mut out, HEAD_END, 0, None, &[], &[], &[])?;
    Ok(out)
}

pub fn write_stored_archive_with_recovery(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
    recovery_percent: u64,
) -> Result<Vec<u8>> {
    validate_recovery_options(options)?;
    validate_recovery_percent(recovery_percent)?;
    if options.features.archive_comment || options.features.quick_open {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 recovery writer option combination",
        });
    }

    let mut recovery_offset = 0;
    for _ in 0..4 {
        let (out, next_recovery_offset) =
            write_stored_archive_recovery_pass(entries, recovery_percent, recovery_offset)?;
        if next_recovery_offset == recovery_offset {
            return Ok(out);
        }
        recovery_offset = next_recovery_offset;
    }
    write_stored_archive_recovery_pass(entries, recovery_percent, recovery_offset)
        .map(|(out, _)| out)
}

fn write_stored_archive_recovery_pass(
    entries: &[StoredEntry<'_>],
    recovery_percent: u64,
    recovery_offset: u64,
) -> Result<(Vec<u8>, u64)> {
    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);

    let mut main_extra = Vec::new();
    write_locator_record(&mut main_extra, None, Some(recovery_offset));
    write_main_header(&mut out, MHFL_RECOVERY, None, &main_extra)?;
    for entry in entries {
        write_stored_entry(&mut out, entry)?;
    }

    let rr_pos = out.len();
    write_recovery_service(&mut out, recovery_percent)?;
    write_block(&mut out, HEAD_END, 0, None, &[], &[], &[])?;
    Ok((out, (rr_pos - RAR50_SIGNATURE.len()) as u64))
}

pub fn write_stored_archive_with_file_services(
    entries: &[StoredEntryWithServices<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    validate_file_service_options(options)?;
    if options.features.archive_comment || options.features.quick_open {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 file-service writer option combination",
        });
    }

    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    write_main_header(&mut out, 0, None, &[])?;
    for entry in entries {
        write_stored_entry(&mut out, &entry.entry)?;
        for service in entry.services {
            validate_file_service(service)?;
            write_stored_service(&mut out, service.name, service.data)?;
        }
    }
    write_block(&mut out, HEAD_END, 0, None, &[], &[], &[])?;
    Ok(out)
}

pub fn write_encrypted_stored_archive_with_file_services(
    entries: &[EncryptedStoredEntryWithServices<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    validate_encrypted_file_service_options(options)?;
    if options.features.header_encryption {
        return write_header_encrypted_stored_archive_with_file_services(entries);
    }

    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    write_main_header(&mut out, 0, None, &[])?;
    for entry in entries {
        validate_encrypted_entry(&entry.entry)?;
        write_encrypted_stored_entry(&mut out, &entry.entry)?;
        for service in entry.services {
            validate_encrypted_file_service(service)?;
            write_encrypted_stored_service(
                &mut out,
                service.name,
                EncryptedArchiveCommentEntry {
                    data: service.data,
                    password: service.password,
                },
            )?;
        }
    }
    write_block(&mut out, HEAD_END, 0, None, &[], &[], &[])?;
    Ok(out)
}

fn write_header_encrypted_stored_archive_with_file_services(
    entries: &[EncryptedStoredEntryWithServices<'_>],
) -> Result<Vec<u8>> {
    let password = header_encryption_password(entries.iter().flat_map(|entry| {
        std::iter::once(entry.entry.password)
            .chain(entry.services.iter().map(|service| service.password))
    }))?;
    let header_keys = header_encryption_keys(password)?;

    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    write_head_crypt(&mut out, &header_keys)?;
    out.extend_from_slice(&encrypted_main_header_block(
        &header_keys.keys,
        0,
        None,
        &[],
    )?);
    for entry in entries {
        validate_encrypted_entry(&entry.entry)?;
        write_encrypted_stored_entry_with_header_keys(&mut out, &entry.entry, &header_keys.keys)?;
        for service in entry.services {
            validate_encrypted_file_service(service)?;
            write_encrypted_stored_service_with_header_keys(
                &mut out,
                service.name,
                EncryptedArchiveCommentEntry {
                    data: service.data,
                    password: service.password,
                },
                Some(&header_keys.keys),
            )?;
        }
    }
    out.extend_from_slice(&encrypted_header_block(
        &header_keys.keys,
        HEAD_END,
        0,
        None,
        &[],
        &[],
        &[],
    )?);
    Ok(out)
}

fn write_stored_archive_with_quick_open(
    entries: &[StoredEntry<'_>],
    archive_comment: Option<&[u8]>,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
) -> Result<Vec<u8>> {
    let mut locator_offset = 0;
    for _ in 0..4 {
        let (out, next_locator_offset) = write_stored_archive_quick_open_pass(
            entries,
            archive_comment,
            archive_metadata,
            locator_offset,
        )?;
        if next_locator_offset == locator_offset {
            return Ok(out);
        }
        locator_offset = next_locator_offset;
    }
    write_stored_archive_quick_open_pass(entries, archive_comment, archive_metadata, locator_offset)
        .map(|(out, _)| out)
}

fn write_stored_archive_quick_open_pass(
    entries: &[StoredEntry<'_>],
    archive_comment: Option<&[u8]>,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
    locator_offset: u64,
) -> Result<(Vec<u8>, u64)> {
    let mut out = Vec::new();
    let mut cached_headers = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);

    let mut main_extra = Vec::new();
    write_locator_record(&mut main_extra, Some(locator_offset), None);
    if let Some(archive_metadata) = archive_metadata {
        main_extra.extend_from_slice(&archive_metadata_record(archive_metadata)?);
    }
    write_main_header(&mut out, 0, None, &main_extra)?;
    if let Some(comment) = archive_comment {
        write_stored_service_with_cache(&mut out, &mut cached_headers, b"CMT", comment)?;
    }
    for entry in entries {
        write_stored_entry_with_cache(&mut out, &mut cached_headers, entry)?;
    }

    let qo_pos = out.len();
    let qo_payload = quick_open_payload(&cached_headers, qo_pos)?;
    write_stored_service(&mut out, b"QO", &qo_payload)?;
    write_block(&mut out, HEAD_END, 0, None, &[], &[], &[])?;
    Ok((out, (qo_pos - RAR50_SIGNATURE.len()) as u64))
}

pub fn write_encrypted_stored_archive(
    entries: &[EncryptedStoredEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_encrypted_stored_archive_with_comment(entries, options, None)
}

pub fn write_encrypted_compressed_archive(
    entries: &[EncryptedCompressedEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_encrypted_compressed_archive_with_comment_and_metadata(entries, options, None, None)
}

pub fn write_encrypted_compressed_archive_with_metadata(
    entries: &[EncryptedCompressedEntry<'_>],
    options: WriterOptions,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
) -> Result<Vec<u8>> {
    write_encrypted_compressed_archive_with_comment_and_metadata(
        entries,
        options,
        None,
        archive_metadata,
    )
}

pub fn write_encrypted_compressed_archive_with_comment_and_metadata(
    entries: &[EncryptedCompressedEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<EncryptedArchiveCommentEntry<'_>>,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
) -> Result<Vec<u8>> {
    validate_encrypted_compressed_options(options)?;
    if options.features.header_encryption {
        return write_header_encrypted_compressed_archive(
            entries,
            options,
            archive_comment,
            archive_metadata,
        );
    }

    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    let mut main_extra = Vec::new();
    if let Some(archive_metadata) = archive_metadata {
        write_locator_record(&mut main_extra, Some(0), None);
        main_extra.extend_from_slice(&archive_metadata_record(archive_metadata)?);
    }
    let main_flags = if options.features.solid {
        MHFL_SOLID
    } else {
        0
    };
    write_main_header(&mut out, main_flags, None, &main_extra)?;
    if let Some(comment) = archive_comment {
        write_encrypted_stored_service(&mut out, b"CMT", comment)?;
    }
    let algorithm_version = match options.target {
        crate::ArchiveVersion::Rar50 => 0,
        crate::ArchiveVersion::Rar70 => 1,
        _ => return Err(Error::UnsupportedVersion(options.target)),
    };
    let mut solid_encoder = options.features.solid.then(Unpack50Encoder::new);
    for (index, entry) in entries.iter().enumerate() {
        validate_encrypted_compressed_entry(entry)?;
        let packed = if let Some(encoder) = solid_encoder.as_mut() {
            encoder
                .encode_member(entry.data, algorithm_version)
                .map_err(Error::from)?
        } else {
            encode_lz_member(entry.data, algorithm_version).map_err(Error::from)?
        };
        write_encrypted_compressed_entry_payload(
            &mut out,
            entry,
            &packed,
            algorithm_version,
            options.features.solid && index != 0,
            None,
        )?;
    }
    write_block(&mut out, HEAD_END, 0, None, &[], &[], &[])?;
    Ok(out)
}

pub fn write_encrypted_compressed_archive_with_recovery(
    entries: &[EncryptedCompressedEntry<'_>],
    options: WriterOptions,
    recovery_percent: u64,
) -> Result<Vec<u8>> {
    validate_encrypted_compressed_recovery_options(options)?;
    validate_recovery_percent(recovery_percent)?;
    if options.features.header_encryption {
        return write_header_encrypted_compressed_archive_with_recovery(
            entries,
            options,
            recovery_percent,
        );
    }

    let mut recovery_offset = 0;
    for _ in 0..4 {
        let (out, next_recovery_offset) = write_encrypted_compressed_archive_recovery_pass(
            entries,
            options,
            recovery_percent,
            recovery_offset,
        )?;
        if next_recovery_offset == recovery_offset {
            return Ok(out);
        }
        recovery_offset = next_recovery_offset;
    }
    write_encrypted_compressed_archive_recovery_pass(
        entries,
        options,
        recovery_percent,
        recovery_offset,
    )
    .map(|(out, _)| out)
}

fn write_encrypted_compressed_archive_recovery_pass(
    entries: &[EncryptedCompressedEntry<'_>],
    options: WriterOptions,
    recovery_percent: u64,
    recovery_offset: u64,
) -> Result<(Vec<u8>, u64)> {
    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    let mut main_extra = Vec::new();
    write_locator_record(&mut main_extra, None, Some(recovery_offset));
    let main_flags = MHFL_RECOVERY
        | if options.features.solid {
            MHFL_SOLID
        } else {
            0
        };
    write_main_header(&mut out, main_flags, None, &main_extra)?;
    let algorithm_version = match options.target {
        crate::ArchiveVersion::Rar50 => 0,
        crate::ArchiveVersion::Rar70 => 1,
        _ => return Err(Error::UnsupportedVersion(options.target)),
    };
    let mut solid_encoder = options.features.solid.then(Unpack50Encoder::new);
    for (index, entry) in entries.iter().enumerate() {
        validate_encrypted_compressed_entry(entry)?;
        let packed = if let Some(encoder) = solid_encoder.as_mut() {
            encoder
                .encode_member(entry.data, algorithm_version)
                .map_err(Error::from)?
        } else {
            encode_lz_member(entry.data, algorithm_version).map_err(Error::from)?
        };
        write_encrypted_compressed_entry_payload(
            &mut out,
            entry,
            &packed,
            algorithm_version,
            options.features.solid && index != 0,
            None,
        )?;
    }
    let rr_pos = out.len();
    write_recovery_service(&mut out, recovery_percent)?;
    write_block(&mut out, HEAD_END, 0, None, &[], &[], &[])?;
    Ok((out, (rr_pos - RAR50_SIGNATURE.len()) as u64))
}

pub fn write_encrypted_stored_archive_with_comment(
    entries: &[EncryptedStoredEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<EncryptedArchiveCommentEntry<'_>>,
) -> Result<Vec<u8>> {
    write_encrypted_stored_archive_with_comment_and_metadata(
        entries,
        options,
        archive_comment,
        None,
    )
}

pub fn write_encrypted_stored_archive_with_comment_and_metadata(
    entries: &[EncryptedStoredEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<EncryptedArchiveCommentEntry<'_>>,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
) -> Result<Vec<u8>> {
    validate_encrypted_options(options)?;
    if options.features.header_encryption {
        return write_header_encrypted_stored_archive(entries, archive_comment, archive_metadata);
    }

    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    let mut main_extra = Vec::new();
    if let Some(archive_metadata) = archive_metadata {
        write_locator_record(&mut main_extra, Some(0), None);
        main_extra.extend_from_slice(&archive_metadata_record(archive_metadata)?);
    }
    write_main_header(&mut out, 0, None, &main_extra)?;
    if let Some(comment) = archive_comment {
        write_encrypted_stored_service(&mut out, b"CMT", comment)?;
    }
    for entry in entries {
        write_encrypted_stored_entry(&mut out, entry)?;
    }
    write_block(&mut out, HEAD_END, 0, None, &[], &[], &[])?;
    Ok(out)
}

pub fn write_encrypted_stored_archive_with_recovery(
    entries: &[EncryptedStoredEntry<'_>],
    options: WriterOptions,
    recovery_percent: u64,
    recovery_password: &[u8],
) -> Result<Vec<u8>> {
    validate_encrypted_recovery_options(options)?;
    validate_recovery_percent(recovery_percent)?;
    validate_nonempty_password(recovery_password)?;
    if options.features.archive_comment || options.features.quick_open {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 encrypted recovery writer option combination",
        });
    }
    if options.features.header_encryption {
        return write_header_encrypted_stored_archive_with_recovery(
            entries,
            recovery_percent,
            recovery_password,
        );
    }

    let mut recovery_offset = 0;
    for _ in 0..4 {
        let (out, next_recovery_offset) = write_encrypted_stored_archive_recovery_pass(
            entries,
            recovery_percent,
            recovery_offset,
        )?;
        if next_recovery_offset == recovery_offset {
            return Ok(out);
        }
        recovery_offset = next_recovery_offset;
    }
    write_encrypted_stored_archive_recovery_pass(entries, recovery_percent, recovery_offset)
        .map(|(out, _)| out)
}

fn write_encrypted_stored_archive_recovery_pass(
    entries: &[EncryptedStoredEntry<'_>],
    recovery_percent: u64,
    recovery_offset: u64,
) -> Result<(Vec<u8>, u64)> {
    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);

    let mut main_extra = Vec::new();
    write_locator_record(&mut main_extra, None, Some(recovery_offset));
    write_main_header(&mut out, MHFL_RECOVERY, None, &main_extra)?;
    for entry in entries {
        write_encrypted_stored_entry(&mut out, entry)?;
    }

    let rr_pos = out.len();
    write_recovery_service(&mut out, recovery_percent)?;
    write_block(&mut out, HEAD_END, 0, None, &[], &[], &[])?;
    Ok((out, (rr_pos - RAR50_SIGNATURE.len()) as u64))
}

fn write_header_encrypted_stored_archive(
    entries: &[EncryptedStoredEntry<'_>],
    archive_comment: Option<EncryptedArchiveCommentEntry<'_>>,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
) -> Result<Vec<u8>> {
    let password = header_encryption_password(
        entries
            .iter()
            .map(|entry| entry.password)
            .chain(archive_comment.iter().map(|comment| comment.password)),
    )?;
    let header_keys = header_encryption_keys(password)?;

    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    write_head_crypt(&mut out, &header_keys)?;
    let mut main_extra = Vec::new();
    if let Some(archive_metadata) = archive_metadata {
        write_locator_record(&mut main_extra, Some(0), None);
        main_extra.extend_from_slice(&archive_metadata_record(archive_metadata)?);
    }
    out.extend_from_slice(&encrypted_main_header_block(
        &header_keys.keys,
        0,
        None,
        &main_extra,
    )?);
    if let Some(comment) = archive_comment {
        write_encrypted_stored_service_with_header_keys(
            &mut out,
            b"CMT",
            comment,
            Some(&header_keys.keys),
        )?;
    }
    for entry in entries {
        write_encrypted_stored_entry_with_header_keys(&mut out, entry, &header_keys.keys)?;
    }
    out.extend_from_slice(&encrypted_header_block(
        &header_keys.keys,
        HEAD_END,
        0,
        None,
        &[],
        &[],
        &[],
    )?);
    Ok(out)
}

fn write_header_encrypted_compressed_archive(
    entries: &[EncryptedCompressedEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<EncryptedArchiveCommentEntry<'_>>,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
) -> Result<Vec<u8>> {
    let password = header_encryption_password(
        entries
            .iter()
            .map(|entry| entry.password)
            .chain(archive_comment.iter().map(|comment| comment.password)),
    )?;
    let header_keys = header_encryption_keys(password)?;
    let algorithm_version = match options.target {
        crate::ArchiveVersion::Rar50 => 0,
        crate::ArchiveVersion::Rar70 => 1,
        _ => return Err(Error::UnsupportedVersion(options.target)),
    };

    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    write_head_crypt(&mut out, &header_keys)?;
    let mut main_extra = Vec::new();
    if let Some(archive_metadata) = archive_metadata {
        write_locator_record(&mut main_extra, Some(0), None);
        main_extra.extend_from_slice(&archive_metadata_record(archive_metadata)?);
    }
    let main_flags = if options.features.solid {
        MHFL_SOLID
    } else {
        0
    };
    out.extend_from_slice(&encrypted_main_header_block(
        &header_keys.keys,
        main_flags,
        None,
        &main_extra,
    )?);
    if let Some(comment) = archive_comment {
        write_encrypted_stored_service_with_header_keys(
            &mut out,
            b"CMT",
            comment,
            Some(&header_keys.keys),
        )?;
    }
    let mut solid_encoder = options.features.solid.then(Unpack50Encoder::new);
    for (index, entry) in entries.iter().enumerate() {
        validate_encrypted_compressed_entry(entry)?;
        let packed = if let Some(encoder) = solid_encoder.as_mut() {
            encoder
                .encode_member(entry.data, algorithm_version)
                .map_err(Error::from)?
        } else {
            encode_lz_member(entry.data, algorithm_version).map_err(Error::from)?
        };
        write_encrypted_compressed_entry_payload(
            &mut out,
            entry,
            &packed,
            algorithm_version,
            options.features.solid && index != 0,
            Some(&header_keys.keys),
        )?;
    }
    out.extend_from_slice(&encrypted_header_block(
        &header_keys.keys,
        HEAD_END,
        0,
        None,
        &[],
        &[],
        &[],
    )?);
    Ok(out)
}

fn write_header_encrypted_compressed_archive_with_recovery(
    entries: &[EncryptedCompressedEntry<'_>],
    options: WriterOptions,
    recovery_percent: u64,
) -> Result<Vec<u8>> {
    let password = header_encryption_password(entries.iter().map(|entry| entry.password))?;
    let header_keys = header_encryption_keys(password)?;

    let mut recovery_offset = 0;
    for _ in 0..4 {
        let (out, next_recovery_offset) = write_header_encrypted_compressed_archive_recovery_pass(
            entries,
            options,
            recovery_percent,
            &header_keys,
            recovery_offset,
        )?;
        if next_recovery_offset == recovery_offset {
            return Ok(out);
        }
        recovery_offset = next_recovery_offset;
    }
    write_header_encrypted_compressed_archive_recovery_pass(
        entries,
        options,
        recovery_percent,
        &header_keys,
        recovery_offset,
    )
    .map(|(out, _)| out)
}

fn write_header_encrypted_compressed_archive_recovery_pass(
    entries: &[EncryptedCompressedEntry<'_>],
    options: WriterOptions,
    recovery_percent: u64,
    header_keys: &HeaderEncryptionKeys,
    recovery_offset: u64,
) -> Result<(Vec<u8>, u64)> {
    let algorithm_version = match options.target {
        crate::ArchiveVersion::Rar50 => 0,
        crate::ArchiveVersion::Rar70 => 1,
        _ => return Err(Error::UnsupportedVersion(options.target)),
    };

    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    write_head_crypt(&mut out, header_keys)?;
    let mut main_extra = Vec::new();
    write_locator_record(&mut main_extra, None, Some(recovery_offset));
    let main_flags = MHFL_RECOVERY
        | if options.features.solid {
            MHFL_SOLID
        } else {
            0
        };
    out.extend_from_slice(&encrypted_main_header_block(
        &header_keys.keys,
        main_flags,
        None,
        &main_extra,
    )?);
    let mut solid_encoder = options.features.solid.then(Unpack50Encoder::new);
    for (index, entry) in entries.iter().enumerate() {
        validate_encrypted_compressed_entry(entry)?;
        let packed = if let Some(encoder) = solid_encoder.as_mut() {
            encoder
                .encode_member(entry.data, algorithm_version)
                .map_err(Error::from)?
        } else {
            encode_lz_member(entry.data, algorithm_version).map_err(Error::from)?
        };
        write_encrypted_compressed_entry_payload(
            &mut out,
            entry,
            &packed,
            algorithm_version,
            options.features.solid && index != 0,
            Some(&header_keys.keys),
        )?;
    }
    let rr_pos = out.len();
    write_header_encrypted_recovery_service(&mut out, recovery_percent, &header_keys.keys)?;
    out.extend_from_slice(&encrypted_header_block(
        &header_keys.keys,
        HEAD_END,
        0,
        None,
        &[],
        &[],
        &[],
    )?);
    Ok((out, (rr_pos - RAR50_SIGNATURE.len()) as u64))
}

fn write_header_encrypted_stored_archive_with_recovery(
    entries: &[EncryptedStoredEntry<'_>],
    recovery_percent: u64,
    recovery_password: &[u8],
) -> Result<Vec<u8>> {
    let password = header_encryption_password(
        entries
            .iter()
            .map(|entry| entry.password)
            .chain(std::iter::once(recovery_password)),
    )?;
    let header_keys = header_encryption_keys(password)?;

    let mut recovery_offset = 0;
    for _ in 0..4 {
        let (out, next_recovery_offset) = write_header_encrypted_stored_archive_recovery_pass(
            entries,
            recovery_percent,
            &header_keys,
            recovery_offset,
        )?;
        if next_recovery_offset == recovery_offset {
            return Ok(out);
        }
        recovery_offset = next_recovery_offset;
    }
    write_header_encrypted_stored_archive_recovery_pass(
        entries,
        recovery_percent,
        &header_keys,
        recovery_offset,
    )
    .map(|(out, _)| out)
}

fn write_header_encrypted_stored_archive_recovery_pass(
    entries: &[EncryptedStoredEntry<'_>],
    recovery_percent: u64,
    header_keys: &HeaderEncryptionKeys,
    recovery_offset: u64,
) -> Result<(Vec<u8>, u64)> {
    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    write_head_crypt(&mut out, header_keys)?;

    let mut main_extra = Vec::new();
    write_locator_record(&mut main_extra, None, Some(recovery_offset));
    out.extend_from_slice(&encrypted_main_header_block(
        &header_keys.keys,
        MHFL_RECOVERY,
        None,
        &main_extra,
    )?);
    for entry in entries {
        write_encrypted_stored_entry_with_header_keys(&mut out, entry, &header_keys.keys)?;
    }

    let rr_pos = out.len();
    write_header_encrypted_recovery_service(&mut out, recovery_percent, &header_keys.keys)?;
    out.extend_from_slice(&encrypted_header_block(
        &header_keys.keys,
        HEAD_END,
        0,
        None,
        &[],
        &[],
        &[],
    )?);
    Ok((out, (rr_pos - RAR50_SIGNATURE.len()) as u64))
}

pub fn write_stored_volumes(
    entry: StoredEntry<'_>,
    options: WriterOptions,
    max_data_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    write_stored_volumes_impl(entry, options, max_data_per_volume, None)
}

pub fn write_stored_volumes_with_recovery(
    entry: StoredEntry<'_>,
    options: WriterOptions,
    max_data_per_volume: usize,
    recovery_percent: u64,
) -> Result<Vec<Vec<u8>>> {
    validate_recovery_percent(recovery_percent)?;
    write_stored_volumes_impl(entry, options, max_data_per_volume, Some(recovery_percent))
}

fn write_stored_volumes_impl(
    entry: StoredEntry<'_>,
    options: WriterOptions,
    max_data_per_volume: usize,
    recovery_percent: Option<u64>,
) -> Result<Vec<Vec<u8>>> {
    if recovery_percent.is_some() {
        validate_recovery_options(options)?;
    } else {
        validate_options(options)?;
    }
    validate_entry(&entry)?;
    if options.features.archive_comment {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 volume comments",
        });
    }
    if max_data_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 5 volume payload size must be non-zero",
        ));
    }
    if entry.data.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 volume writer needs a non-empty payload",
        ));
    }

    let chunks: Vec<&[u8]> = entry.data.chunks(max_data_per_volume).collect();
    if chunks.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 5 volume writer needs at least two volumes",
        ));
    }

    let mut writer = VolumeSetWriter::new(
        max_data_per_volume,
        options.features.solid,
        None,
        recovery_percent,
    );
    for (index, chunk) in chunks.iter().enumerate() {
        writer.write_member(
            chunk.len(),
            |out, start, end, _split_before, _split_after| {
                debug_assert_eq!(start, 0);
                debug_assert_eq!(end, chunk.len());
                write_stored_entry_fragment(
                    out,
                    &entry,
                    chunk,
                    entry.data.len() as u64,
                    None,
                    index > 0,
                    index + 1 < chunks.len(),
                )
            },
        )?;
    }

    writer.finish()
}

pub fn write_compressed_volumes(
    entry: CompressedEntry<'_>,
    options: WriterOptions,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    write_compressed_volume_set(&[entry], options, max_packed_per_volume)
}

pub fn write_compressed_volume_set(
    entries: &[CompressedEntry<'_>],
    options: WriterOptions,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    write_compressed_volume_set_impl(entries, options, max_packed_per_volume, None)
}

pub fn write_compressed_volume_set_with_recovery(
    entries: &[CompressedEntry<'_>],
    options: WriterOptions,
    max_packed_per_volume: usize,
    recovery_percent: u64,
) -> Result<Vec<Vec<u8>>> {
    validate_recovery_percent(recovery_percent)?;
    write_compressed_volume_set_impl(
        entries,
        options,
        max_packed_per_volume,
        Some(recovery_percent),
    )
}

fn write_compressed_volume_set_impl(
    entries: &[CompressedEntry<'_>],
    options: WriterOptions,
    max_packed_per_volume: usize,
    recovery_percent: Option<u64>,
) -> Result<Vec<Vec<u8>>> {
    if recovery_percent.is_some() {
        validate_compressed_recovery_options(options)?;
    } else {
        validate_compressed_options(options)?;
    }
    if max_packed_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 5 compressed volume payload size must be non-zero",
        ));
    }
    if entries.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 compressed volume writer needs at least one entry",
        ));
    }
    if entries.iter().any(|entry| entry.data.is_empty()) {
        return Err(Error::InvalidHeader(
            "RAR 5 compressed volume writer needs a non-empty payload",
        ));
    }

    let algorithm_version = match options.target {
        crate::ArchiveVersion::Rar50 => 0,
        crate::ArchiveVersion::Rar70 => 1,
        _ => return Err(Error::UnsupportedVersion(options.target)),
    };

    let mut encoder = options.features.solid.then(Unpack50Encoder::new);
    let mut members = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        validate_compressed_entry(entry)?;
        let packed = if let Some(encoder) = encoder.as_mut() {
            encoder
                .encode_member(entry.data, algorithm_version)
                .map_err(Error::from)?
        } else {
            encode_lz_member(entry.data, algorithm_version).map_err(Error::from)?
        };
        members.push(CompressedVolumeMember {
            entry_index: index,
            packed,
            solid_continuation: options.features.solid && index != 0,
        });
    }

    let mut writer = VolumeSetWriter::new(
        max_packed_per_volume,
        options.features.solid,
        None,
        recovery_percent,
    );
    for member in &members {
        writer.write_member(
            member.packed.len(),
            |out, start, end, split_before, split_after| {
                write_compressed_entry_fragment(
                    out,
                    &entries[member.entry_index],
                    &member.packed[start..end],
                    algorithm_version,
                    member.solid_continuation,
                    split_before,
                    split_after,
                )
            },
        )?;
    }
    let volumes = writer.finish()?;
    if volumes.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 5 compressed volume writer needs at least two volumes",
        ));
    }
    Ok(volumes)
}

pub fn write_encrypted_stored_volumes(
    entry: EncryptedStoredEntry<'_>,
    options: WriterOptions,
    max_encrypted_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    write_encrypted_stored_volumes_impl(entry, options, max_encrypted_per_volume, None)
}

pub fn write_encrypted_stored_volumes_with_recovery(
    entry: EncryptedStoredEntry<'_>,
    options: WriterOptions,
    max_encrypted_per_volume: usize,
    recovery_percent: u64,
) -> Result<Vec<Vec<u8>>> {
    validate_recovery_percent(recovery_percent)?;
    write_encrypted_stored_volumes_impl(
        entry,
        options,
        max_encrypted_per_volume,
        Some(recovery_percent),
    )
}

fn write_encrypted_stored_volumes_impl(
    entry: EncryptedStoredEntry<'_>,
    options: WriterOptions,
    max_encrypted_per_volume: usize,
    recovery_percent: Option<u64>,
) -> Result<Vec<Vec<u8>>> {
    if recovery_percent.is_some() {
        validate_encrypted_recovery_options(options)?;
        if options.features.header_encryption {
            return Err(Error::UnsupportedFeature {
                version: options.target,
                feature: "RAR 5 header-encrypted volume recovery writer",
            });
        }
    } else {
        validate_encrypted_options(options)?;
    }
    validate_encrypted_entry(&entry)?;
    if options.features.archive_comment {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 volume comments",
        });
    }
    if max_encrypted_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted volume payload size must be non-zero",
        ));
    }
    if entry.data.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted volume writer needs a non-empty payload",
        ));
    }

    let encrypted = encrypted_stored_payload(entry.data, entry.password)?;
    let chunks: Vec<&[u8]> = encrypted.data.chunks(max_encrypted_per_volume).collect();
    if chunks.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted volume writer needs at least two volumes",
        ));
    }

    let header_keys = if options.features.header_encryption {
        Some(header_encryption_keys(entry.password)?)
    } else {
        None
    };

    let mut writer = VolumeSetWriter::new(
        max_encrypted_per_volume,
        options.features.solid,
        header_keys.as_ref(),
        recovery_percent,
    );
    for (index, chunk) in chunks.iter().enumerate() {
        writer.write_member(
            chunk.len(),
            |out, start, end, _split_before, _split_after| {
                debug_assert_eq!(start, 0);
                debug_assert_eq!(end, chunk.len());
                write_encrypted_stored_entry_fragment_with_header_keys(
                    out,
                    &entry,
                    chunk,
                    &encrypted,
                    index > 0,
                    index + 1 < chunks.len(),
                    header_keys.as_ref().map(|keys| &keys.keys),
                )
            },
        )?;
    }

    writer.finish()
}

pub fn write_encrypted_compressed_volumes(
    entry: EncryptedCompressedEntry<'_>,
    options: WriterOptions,
    max_encrypted_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    write_encrypted_compressed_volume_set(&[entry], options, max_encrypted_per_volume)
}

pub fn write_encrypted_compressed_volume_set(
    entries: &[EncryptedCompressedEntry<'_>],
    options: WriterOptions,
    max_encrypted_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    write_encrypted_compressed_volume_set_impl(entries, options, max_encrypted_per_volume, None)
}

pub fn write_encrypted_compressed_volume_set_with_recovery(
    entries: &[EncryptedCompressedEntry<'_>],
    options: WriterOptions,
    max_encrypted_per_volume: usize,
    recovery_percent: u64,
) -> Result<Vec<Vec<u8>>> {
    validate_recovery_percent(recovery_percent)?;
    write_encrypted_compressed_volume_set_impl(
        entries,
        options,
        max_encrypted_per_volume,
        Some(recovery_percent),
    )
}

fn write_encrypted_compressed_volume_set_impl(
    entries: &[EncryptedCompressedEntry<'_>],
    options: WriterOptions,
    max_encrypted_per_volume: usize,
    recovery_percent: Option<u64>,
) -> Result<Vec<Vec<u8>>> {
    if recovery_percent.is_some() {
        validate_encrypted_compressed_recovery_options(options)?;
        if options.features.header_encryption {
            return Err(Error::UnsupportedFeature {
                version: options.target,
                feature: "RAR 5 header-encrypted compressed volume recovery writer",
            });
        }
    } else {
        validate_encrypted_compressed_options(options)?;
    }
    if max_encrypted_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted compressed volume payload size must be non-zero",
        ));
    }
    if entries.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted compressed volume writer needs at least one entry",
        ));
    }
    if entries.iter().any(|entry| entry.data.is_empty()) {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted compressed volume writer needs a non-empty payload",
        ));
    }

    let algorithm_version = match options.target {
        crate::ArchiveVersion::Rar50 => 0,
        crate::ArchiveVersion::Rar70 => 1,
        _ => return Err(Error::UnsupportedVersion(options.target)),
    };

    let mut solid_encoder = options.features.solid.then(Unpack50Encoder::new);
    let mut members = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        validate_encrypted_compressed_entry(entry)?;
        let packed = if let Some(encoder) = solid_encoder.as_mut() {
            encoder
                .encode_member(entry.data, algorithm_version)
                .map_err(Error::from)?
        } else {
            encode_lz_member(entry.data, algorithm_version).map_err(Error::from)?
        };
        let encrypted = encrypted_payload(&packed, entry.data, entry.password)?;
        members.push(EncryptedCompressedVolumeMember {
            entry_index: index,
            encrypted,
            solid_continuation: options.features.solid && index != 0,
        });
    }

    let password = header_encryption_password(entries.iter().map(|entry| entry.password))?;
    let header_keys = if options.features.header_encryption {
        Some(header_encryption_keys(password)?)
    } else {
        None
    };

    let mut writer = VolumeSetWriter::new(
        max_encrypted_per_volume,
        options.features.solid,
        header_keys.as_ref(),
        recovery_percent,
    );
    for member in &members {
        writer.write_member(
            member.encrypted.data.len(),
            |out, start, end, split_before, split_after| {
                write_encrypted_compressed_entry_fragment_with_header_keys(
                    out,
                    EncryptedCompressedFragment {
                        entry: &entries[member.entry_index],
                        data: &member.encrypted.data[start..end],
                        encrypted: &member.encrypted,
                        algorithm_version,
                        solid_continuation: member.solid_continuation,
                        split_before,
                        split_after,
                    },
                    header_keys.as_ref().map(|keys| &keys.keys),
                )
            },
        )?;
    }
    let volumes = writer.finish()?;
    if volumes.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted compressed volume writer needs at least two volumes",
        ));
    }
    Ok(volumes)
}

fn write_main_header(
    out: &mut Vec<u8>,
    archive_flags: u64,
    volume_number: Option<u64>,
    extra: &[u8],
) -> Result<()> {
    let mut specific = Vec::new();
    write_vint(&mut specific, archive_flags);
    if let Some(volume_number) = volume_number {
        write_vint(&mut specific, volume_number);
    }
    write_block(
        out,
        HEAD_MAIN,
        if extra.is_empty() { 0 } else { HFL_EXTRA },
        None,
        &specific,
        extra,
        &[],
    )
}

fn encrypted_main_header_block(
    keys: &Rar50Keys,
    archive_flags: u64,
    volume_number: Option<u64>,
    extra: &[u8],
) -> Result<Vec<u8>> {
    let mut specific = Vec::new();
    write_vint(&mut specific, archive_flags);
    if let Some(volume_number) = volume_number {
        write_vint(&mut specific, volume_number);
    }
    encrypted_header_block(
        keys,
        HEAD_MAIN,
        if extra.is_empty() { 0 } else { HFL_EXTRA },
        None,
        &specific,
        extra,
        &[],
    )
}

fn encode_member_with_filter_policy(
    data: &[u8],
    algorithm_version: u8,
    policy: FilterPolicy,
) -> Result<Vec<u8>> {
    match policy {
        FilterPolicy::None => encode_lz_member(data, algorithm_version).map_err(Error::from),
        FilterPolicy::Explicit(filter) => {
            encode_member_with_filter(data, algorithm_version, filter).map_err(Error::from)
        }
        FilterPolicy::AutoSize => encode_member_with_auto_size_filter(data, algorithm_version),
    }
}

fn encode_member_with_auto_size_filter(data: &[u8], algorithm_version: u8) -> Result<Vec<u8>> {
    let mut best = encode_lz_member(data, algorithm_version).map_err(Error::from)?;
    let mut candidates = vec![FilterKind::E8, FilterKind::E8E9, FilterKind::Arm];
    for channels in 1..=4 {
        candidates.push(FilterKind::Delta { channels });
    }
    for filter in candidates {
        let packed =
            encode_member_with_filter(data, algorithm_version, filter).map_err(Error::from)?;
        if packed.len() < best.len() {
            best = packed;
        }
    }
    Ok(best)
}

fn encode_member_with_filter(
    data: &[u8],
    algorithm_version: u8,
    filter: FilterKind,
) -> rars_codec::Result<Vec<u8>> {
    match filter {
        FilterKind::Delta { channels } => {
            encode_lz_member_with_delta_filter(data, channels, algorithm_version)
        }
        FilterKind::E8 => encode_lz_member_with_e8_filter(data, false, algorithm_version),
        FilterKind::E8E9 => encode_lz_member_with_e8_filter(data, true, algorithm_version),
        FilterKind::Arm => encode_lz_member_with_arm_filter(data, algorithm_version),
    }
}

struct CompressedVolumeMember {
    entry_index: usize,
    packed: Vec<u8>,
    solid_continuation: bool,
}

struct EncryptedCompressedVolumeMember {
    entry_index: usize,
    encrypted: EncryptedStoredPayload,
    solid_continuation: bool,
}

struct VolumeSetWriter<'a> {
    max_payload_per_volume: usize,
    solid: bool,
    header_keys: Option<&'a HeaderEncryptionKeys>,
    recovery_percent: Option<u64>,
    volumes: Vec<Vec<u8>>,
    current_body: Option<Vec<u8>>,
    current_payload_len: usize,
    current_volume_number: Option<u64>,
}

impl<'a> VolumeSetWriter<'a> {
    fn new(
        max_payload_per_volume: usize,
        solid: bool,
        header_keys: Option<&'a HeaderEncryptionKeys>,
        recovery_percent: Option<u64>,
    ) -> Self {
        Self {
            max_payload_per_volume,
            solid,
            header_keys,
            recovery_percent,
            volumes: Vec::new(),
            current_body: None,
            current_payload_len: 0,
            current_volume_number: None,
        }
    }

    fn write_member<F>(&mut self, member_len: usize, mut write_fragment: F) -> Result<()>
    where
        F: FnMut(&mut Vec<u8>, usize, usize, bool, bool) -> Result<()>,
    {
        let mut start = 0;
        let mut split_before = false;
        while start < member_len {
            if self.current_body.is_none()
                || self.current_payload_len == self.max_payload_per_volume
            {
                self.start_volume()?;
            }
            let remaining_volume = self.max_payload_per_volume - self.current_payload_len;
            let remaining_member = member_len - start;
            let fragment_len = remaining_volume.min(remaining_member);
            let end = start + fragment_len;
            let split_after = end < member_len;

            let out = self.current_body.as_mut().expect("volume started");
            write_fragment(out, start, end, split_before, split_after)?;
            self.current_payload_len += fragment_len;
            start = end;
            split_before = true;

            if self.current_payload_len == self.max_payload_per_volume {
                self.finish_current_volume()?;
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<Vec<u8>>> {
        if self.current_body.is_some() {
            self.finish_current_volume()?;
        }
        Ok(self.volumes)
    }

    fn start_volume(&mut self) -> Result<()> {
        debug_assert!(self.current_body.is_none());
        let volume_number = self.volumes.len() as u64;
        self.current_body = Some(Vec::new());
        self.current_payload_len = 0;
        self.current_volume_number = Some(volume_number);
        Ok(())
    }

    fn finish_current_volume(&mut self) -> Result<()> {
        let body = self.current_body.take().expect("volume started");
        let volume_number = self
            .current_volume_number
            .take()
            .expect("volume number set");
        let out = write_volume_from_body(
            &body,
            volume_number,
            self.solid,
            self.header_keys,
            self.recovery_percent,
        )?;
        self.volumes.push(out);
        self.current_payload_len = 0;
        Ok(())
    }
}

fn write_volume_from_body(
    body: &[u8],
    volume_number: u64,
    solid: bool,
    header_keys: Option<&HeaderEncryptionKeys>,
    recovery_percent: Option<u64>,
) -> Result<Vec<u8>> {
    let mut recovery_offset = 0;
    for _ in 0..4 {
        let (out, next_recovery_offset) = write_volume_from_body_pass(
            body,
            volume_number,
            solid,
            header_keys,
            recovery_percent,
            recovery_offset,
        )?;
        if recovery_percent.is_none() || next_recovery_offset == recovery_offset {
            return Ok(out);
        }
        recovery_offset = next_recovery_offset;
    }
    write_volume_from_body_pass(
        body,
        volume_number,
        solid,
        header_keys,
        recovery_percent,
        recovery_offset,
    )
    .map(|(out, _)| out)
}

fn write_volume_from_body_pass(
    body: &[u8],
    volume_number: u64,
    solid: bool,
    header_keys: Option<&HeaderEncryptionKeys>,
    recovery_percent: Option<u64>,
    recovery_offset: u64,
) -> Result<(Vec<u8>, u64)> {
    let mut out = Vec::new();
    out.extend_from_slice(RAR50_SIGNATURE);
    let mut main_extra = Vec::new();
    if recovery_percent.is_some() {
        write_locator_record(&mut main_extra, None, Some(recovery_offset));
    }
    let main_flags = MHFL_VOLUME
        | MHFL_VOLUME_NUMBER
        | if solid { MHFL_SOLID } else { 0 }
        | if recovery_percent.is_some() {
            MHFL_RECOVERY
        } else {
            0
        };
    if let Some(header_keys) = header_keys {
        write_head_crypt(&mut out, header_keys)?;
        out.extend_from_slice(&encrypted_main_header_block(
            &header_keys.keys,
            main_flags,
            Some(volume_number),
            &main_extra,
        )?);
    } else {
        write_main_header(&mut out, main_flags, Some(volume_number), &main_extra)?;
    }
    out.extend_from_slice(body);
    let recovery_offset = if let Some(recovery_percent) = recovery_percent {
        let rr_pos = out.len();
        if let Some(header_keys) = header_keys {
            write_header_encrypted_recovery_service(&mut out, recovery_percent, &header_keys.keys)?;
        } else {
            write_recovery_service(&mut out, recovery_percent)?;
        }
        (rr_pos - RAR50_SIGNATURE.len()) as u64
    } else {
        0
    };
    if let Some(header_keys) = header_keys {
        out.extend_from_slice(&encrypted_header_block(
            &header_keys.keys,
            HEAD_END,
            0,
            None,
            &[],
            &[],
            &[],
        )?);
    } else {
        write_block(&mut out, HEAD_END, 0, None, &[], &[], &[])?;
    }
    Ok((out, recovery_offset))
}

fn validate_options(options: WriterOptions) -> Result<()> {
    validate_plain_options(options, false)
}

fn validate_recovery_options(options: WriterOptions) -> Result<()> {
    validate_plain_options(options, true)
}

fn validate_plain_options(options: WriterOptions, allow_recovery_record: bool) -> Result<()> {
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = crate::FeatureSet::store_only();
    allowed.archive_comment = options.features.archive_comment;
    allowed.quick_open = options.features.quick_open;
    if allow_recovery_record {
        allowed.recovery_record = options.features.recovery_record;
    }
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 writer feature",
        });
    }
    Ok(())
}

fn validate_file_service_options(options: WriterOptions) -> Result<()> {
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = crate::FeatureSet::store_only();
    allowed.file_comment = options.features.file_comment;
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 stored file-service writer feature",
        });
    }
    Ok(())
}

fn validate_compressed_options(options: WriterOptions) -> Result<()> {
    validate_compressed_feature_options(options, false)
}

fn validate_compressed_recovery_options(options: WriterOptions) -> Result<()> {
    validate_compressed_feature_options(options, true)
}

fn validate_compressed_feature_options(
    options: WriterOptions,
    allow_recovery_record: bool,
) -> Result<()> {
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = crate::FeatureSet::store_only();
    allowed.solid = options.features.solid;
    allowed.archive_comment = options.features.archive_comment;
    if allow_recovery_record {
        allowed.recovery_record = options.features.recovery_record;
    }
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 compressed writer feature",
        });
    }
    Ok(())
}

fn solid_compression_flag(solid_continuation: bool) -> u64 {
    if solid_continuation {
        0x40
    } else {
        0
    }
}

fn validate_encrypted_compressed_options(options: WriterOptions) -> Result<()> {
    validate_encrypted_compressed_feature_options(options, false)
}

fn validate_encrypted_compressed_recovery_options(options: WriterOptions) -> Result<()> {
    validate_encrypted_compressed_feature_options(options, true)
}

fn validate_encrypted_compressed_feature_options(
    options: WriterOptions,
    allow_recovery_record: bool,
) -> Result<()> {
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = crate::FeatureSet::store_only();
    allowed.file_encryption = true;
    allowed.header_encryption = options.features.header_encryption;
    allowed.solid = options.features.solid;
    allowed.archive_comment = options.features.archive_comment;
    if allow_recovery_record {
        allowed.recovery_record = options.features.recovery_record;
    }
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 encrypted compressed writer feature",
        });
    }
    Ok(())
}

struct CachedHeader {
    offset: usize,
    header: Vec<u8>,
}

struct BlockParts<'a> {
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &'a [u8],
    extra: &'a [u8],
    data: &'a [u8],
}

fn validate_encrypted_options(options: WriterOptions) -> Result<()> {
    validate_encrypted_feature_options(options, false)
}

fn validate_encrypted_recovery_options(options: WriterOptions) -> Result<()> {
    validate_encrypted_feature_options(options, true)
}

fn validate_encrypted_feature_options(
    options: WriterOptions,
    allow_recovery_record: bool,
) -> Result<()> {
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = crate::FeatureSet::store_only();
    allowed.file_encryption = true;
    allowed.header_encryption = options.features.header_encryption;
    allowed.archive_comment = options.features.archive_comment;
    if allow_recovery_record {
        allowed.recovery_record = options.features.recovery_record;
    }
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 encrypted stored writer feature",
        });
    }
    Ok(())
}

fn validate_encrypted_file_service_options(options: WriterOptions) -> Result<()> {
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = crate::FeatureSet::store_only();
    allowed.file_encryption = true;
    allowed.header_encryption = options.features.header_encryption;
    allowed.file_comment = options.features.file_comment;
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 encrypted stored file-service writer feature",
        });
    }
    Ok(())
}

struct HeaderEncryptionKeys {
    keys: Rar50Keys,
    salt: [u8; 16],
}

fn header_encryption_keys(password: &[u8]) -> Result<HeaderEncryptionKeys> {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt)
        .map_err(|_| Error::InvalidHeader("RAR 5 writer could not generate encryption salt"))?;
    let keys = Rar50Keys::derive(password, salt, 0).map_err(map_rar50_crypto_error)?;
    Ok(HeaderEncryptionKeys { keys, salt })
}

fn header_encryption_password<'a>(
    mut passwords: impl Iterator<Item = &'a [u8]>,
) -> Result<&'a [u8]> {
    let first = passwords.next().ok_or(Error::NeedPassword)?;
    for password in passwords {
        if password != first {
            return Err(Error::InvalidHeader(
                "RAR 5 header-encrypted writer needs one shared password",
            ));
        }
    }
    Ok(first)
}

fn write_head_crypt(out: &mut Vec<u8>, header_keys: &HeaderEncryptionKeys) -> Result<()> {
    let mut specific = Vec::new();
    write_vint(&mut specific, 0);
    write_vint(&mut specific, 0x0001);
    specific.push(0);
    specific.extend_from_slice(&header_keys.salt);
    specific.extend_from_slice(&header_keys.keys.password_check_record());
    write_block(out, HEAD_CRYPT, 0, None, &specific, &[], &[])
}

fn archive_metadata_record(metadata: ArchiveMetadataEntry<'_>) -> Result<Vec<u8>> {
    if metadata.name.is_none() && metadata.creation_time.is_none() {
        return Err(Error::InvalidHeader(
            "RAR 5 archive metadata writer needs a name or creation time",
        ));
    }
    if metadata.name.is_some() && metadata.creation_time.is_none() {
        return Err(Error::InvalidHeader(
            "RAR 5 archive metadata name needs a creation time",
        ));
    }
    let mut flags = 0;
    if metadata.name.is_some() {
        flags |= MHEXTRA_ARCHIVE_METADATA_NAME;
    }
    if metadata.creation_time.is_some() {
        flags |= MHEXTRA_ARCHIVE_METADATA_TIME;
    }

    let mut record = Vec::new();
    write_vint(&mut record, flags);
    if let Some(name) = metadata.name {
        if name.is_empty() {
            return Err(Error::InvalidHeader("RAR 5 archive metadata name is empty"));
        }
        write_vint(&mut record, name.len() as u64);
        record.extend_from_slice(name);
    }
    if flags & MHEXTRA_ARCHIVE_METADATA_TIME != 0 {
        record.extend_from_slice(&metadata.creation_time.unwrap().to_le_bytes());
    }

    let mut extra = Vec::new();
    write_extra_record(&mut extra, MHEXTRA_ARCHIVE_METADATA, &record);
    Ok(extra)
}

fn write_locator_record(
    out: &mut Vec<u8>,
    quick_open_offset: Option<u64>,
    recovery_record_offset: Option<u64>,
) {
    let mut flags = 0;
    if quick_open_offset.is_some() {
        flags |= MHEXTRA_LOCATOR_QUICK_OPEN;
    }
    if recovery_record_offset.is_some() {
        flags |= MHEXTRA_LOCATOR_RECOVERY;
    }

    let mut record = Vec::new();
    write_vint(&mut record, flags);
    if let Some(quick_open_offset) = quick_open_offset {
        write_vint(&mut record, quick_open_offset);
    }
    if let Some(recovery_record_offset) = recovery_record_offset {
        write_vint(&mut record, recovery_record_offset);
    }
    write_extra_record(out, MHEXTRA_LOCATOR, &record);
}

fn write_stored_entry(out: &mut Vec<u8>, entry: &StoredEntry<'_>) -> Result<()> {
    validate_entry(entry)?;
    write_stored_entry_fragment(
        out,
        entry,
        entry.data,
        entry.data.len() as u64,
        Some(crc32(entry.data)),
        false,
        false,
    )
}

fn write_compressed_entry_payload(
    out: &mut Vec<u8>,
    entry: &CompressedEntry<'_>,
    packed: &[u8],
    algorithm_version: u8,
    solid_continuation: bool,
) -> Result<()> {
    let mut extra = Vec::new();
    write_hash_record(&mut extra, entry.data);
    let compression_info =
        u64::from(algorithm_version) | (1 << 7) | solid_compression_flag(solid_continuation);
    let specific = file_specific(
        entry.name,
        entry.data.len() as u64,
        Some(crc32(entry.data)),
        entry.attributes,
        entry.mtime,
        compression_info,
        entry.host_os,
    )?;
    write_block(
        out,
        HEAD_FILE,
        HFL_EXTRA | HFL_DATA,
        Some(packed.len() as u64),
        &specific,
        &extra,
        packed,
    )
}

fn write_compressed_entry_fragment(
    out: &mut Vec<u8>,
    entry: &CompressedEntry<'_>,
    data: &[u8],
    algorithm_version: u8,
    solid_continuation: bool,
    split_before: bool,
    split_after: bool,
) -> Result<()> {
    let mut extra = Vec::new();
    if !split_after {
        write_hash_record(&mut extra, entry.data);
    }
    let compression_info =
        u64::from(algorithm_version) | (1 << 7) | solid_compression_flag(solid_continuation);
    let specific = file_specific(
        entry.name,
        entry.data.len() as u64,
        (!split_after).then_some(crc32(entry.data)),
        entry.attributes,
        entry.mtime,
        compression_info,
        entry.host_os,
    )?;
    let mut block_flags = HFL_DATA;
    if split_before {
        block_flags |= HFL_SPLIT_BEFORE;
    }
    if split_after {
        block_flags |= HFL_SPLIT_AFTER;
    }
    if !extra.is_empty() {
        block_flags |= HFL_EXTRA;
    }

    write_block(
        out,
        HEAD_FILE,
        block_flags,
        Some(data.len() as u64),
        &specific,
        &extra,
        data,
    )
}

fn write_stored_entry_with_cache(
    out: &mut Vec<u8>,
    cached_headers: &mut Vec<CachedHeader>,
    entry: &StoredEntry<'_>,
) -> Result<()> {
    validate_entry(entry)?;
    let mut extra = Vec::new();
    write_hash_record(&mut extra, entry.data);
    let specific = stored_file_specific(
        entry.name,
        entry.data.len() as u64,
        Some(crc32(entry.data)),
        entry.attributes,
        entry.mtime,
        entry.host_os,
    )?;
    write_block_with_cache(
        out,
        cached_headers,
        BlockParts {
            header_type: HEAD_FILE,
            flags: HFL_EXTRA | HFL_DATA,
            data_size: Some(entry.data.len() as u64),
            type_specific: &specific,
            extra: &extra,
            data: entry.data,
        },
    )
}

fn write_encrypted_stored_entry(out: &mut Vec<u8>, entry: &EncryptedStoredEntry<'_>) -> Result<()> {
    validate_encrypted_entry(entry)?;
    let encrypted = encrypted_stored_payload(entry.data, entry.password)?;

    write_encrypted_stored_entry_fragment(out, entry, &encrypted.data, &encrypted, false, false)
}

fn write_encrypted_compressed_entry_payload(
    out: &mut Vec<u8>,
    entry: &EncryptedCompressedEntry<'_>,
    packed: &[u8],
    algorithm_version: u8,
    solid_continuation: bool,
    header_keys: Option<&Rar50Keys>,
) -> Result<()> {
    let encrypted = encrypted_payload(packed, entry.data, entry.password)?;

    let mut extra = Vec::new();
    write_file_encryption_record(
        &mut extra,
        encrypted.salt,
        encrypted.iv,
        encrypted.check_value,
    );
    write_hash_record_with_value(&mut extra, encrypted.blake2sp_mac);
    let compression_info =
        u64::from(algorithm_version) | (1 << 7) | solid_compression_flag(solid_continuation);
    let specific = file_specific(
        entry.name,
        entry.data.len() as u64,
        Some(encrypted.crc32_mac),
        entry.attributes,
        entry.mtime,
        compression_info,
        entry.host_os,
    )?;
    if let Some(header_keys) = header_keys {
        out.extend_from_slice(&encrypted_header_block(
            header_keys,
            HEAD_FILE,
            HFL_EXTRA | HFL_DATA,
            Some(encrypted.data.len() as u64),
            &specific,
            &extra,
            &encrypted.data,
        )?);
        Ok(())
    } else {
        write_block(
            out,
            HEAD_FILE,
            HFL_EXTRA | HFL_DATA,
            Some(encrypted.data.len() as u64),
            &specific,
            &extra,
            &encrypted.data,
        )
    }
}

fn write_encrypted_stored_entry_with_header_keys(
    out: &mut Vec<u8>,
    entry: &EncryptedStoredEntry<'_>,
    header_keys: &Rar50Keys,
) -> Result<()> {
    validate_encrypted_entry(entry)?;
    let encrypted = encrypted_stored_payload(entry.data, entry.password)?;
    write_encrypted_stored_entry_fragment_with_header_keys(
        out,
        entry,
        &encrypted.data,
        &encrypted,
        false,
        false,
        Some(header_keys),
    )
}

struct EncryptedStoredPayload {
    data: Vec<u8>,
    salt: [u8; 16],
    iv: [u8; 16],
    check_value: [u8; 12],
    crc32_mac: u32,
    blake2sp_mac: [u8; 32],
}

fn encrypted_stored_payload(data: &[u8], password: &[u8]) -> Result<EncryptedStoredPayload> {
    encrypted_payload(data, data, password)
}

fn encrypted_payload(
    packed_data: &[u8],
    integrity_data: &[u8],
    password: &[u8],
) -> Result<EncryptedStoredPayload> {
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 16];
    getrandom::getrandom(&mut salt)
        .map_err(|_| Error::InvalidHeader("RAR 5 writer could not generate encryption salt"))?;
    getrandom::getrandom(&mut iv)
        .map_err(|_| Error::InvalidHeader("RAR 5 writer could not generate encryption IV"))?;
    let keys = Rar50Keys::derive(password, salt, 0).map_err(map_rar50_crypto_error)?;

    let mut encrypted_data = packed_data.to_vec();
    let padded_len = encrypted_data
        .len()
        .checked_add(15)
        .ok_or(Error::InvalidHeader("RAR 5 encrypted data size overflows"))?
        & !15;
    encrypted_data.resize(padded_len, 0);
    Rar50Cipher::new(keys.key, iv).encrypt_in_place(&mut encrypted_data);

    Ok(EncryptedStoredPayload {
        data: encrypted_data,
        salt,
        iv,
        check_value: keys.password_check_record(),
        crc32_mac: keys.mac_crc32(crc32(integrity_data)),
        blake2sp_mac: keys.mac_hash32(blake2sp::hash(integrity_data)),
    })
}

fn write_encrypted_stored_entry_fragment(
    out: &mut Vec<u8>,
    entry: &EncryptedStoredEntry<'_>,
    data: &[u8],
    encrypted: &EncryptedStoredPayload,
    split_before: bool,
    split_after: bool,
) -> Result<()> {
    write_encrypted_stored_entry_fragment_with_header_keys(
        out,
        entry,
        data,
        encrypted,
        split_before,
        split_after,
        None,
    )
}

fn write_encrypted_stored_entry_fragment_with_header_keys(
    out: &mut Vec<u8>,
    entry: &EncryptedStoredEntry<'_>,
    data: &[u8],
    encrypted: &EncryptedStoredPayload,
    split_before: bool,
    split_after: bool,
    header_keys: Option<&Rar50Keys>,
) -> Result<()> {
    let mut extra = Vec::new();
    write_file_encryption_record(
        &mut extra,
        encrypted.salt,
        encrypted.iv,
        encrypted.check_value,
    );
    if !split_after {
        write_hash_record_with_value(&mut extra, encrypted.blake2sp_mac);
    }

    let specific = stored_file_specific(
        entry.name,
        entry.data.len() as u64,
        (!split_after).then_some(encrypted.crc32_mac),
        entry.attributes,
        entry.mtime,
        entry.host_os,
    )?;
    let mut block_flags = HFL_EXTRA | HFL_DATA;
    if split_before {
        block_flags |= HFL_SPLIT_BEFORE;
    }
    if split_after {
        block_flags |= HFL_SPLIT_AFTER;
    }

    if let Some(header_keys) = header_keys {
        out.extend_from_slice(&encrypted_header_block(
            header_keys,
            HEAD_FILE,
            block_flags,
            Some(data.len() as u64),
            &specific,
            &extra,
            data,
        )?);
        Ok(())
    } else {
        write_block(
            out,
            HEAD_FILE,
            block_flags,
            Some(data.len() as u64),
            &specific,
            &extra,
            data,
        )
    }
}

struct EncryptedCompressedFragment<'a, 'b> {
    entry: &'a EncryptedCompressedEntry<'b>,
    data: &'a [u8],
    encrypted: &'a EncryptedStoredPayload,
    algorithm_version: u8,
    solid_continuation: bool,
    split_before: bool,
    split_after: bool,
}

fn write_encrypted_compressed_entry_fragment_with_header_keys(
    out: &mut Vec<u8>,
    fragment: EncryptedCompressedFragment<'_, '_>,
    header_keys: Option<&Rar50Keys>,
) -> Result<()> {
    let EncryptedCompressedFragment {
        entry,
        data,
        encrypted,
        algorithm_version,
        solid_continuation,
        split_before,
        split_after,
    } = fragment;

    let mut extra = Vec::new();
    write_file_encryption_record(
        &mut extra,
        encrypted.salt,
        encrypted.iv,
        encrypted.check_value,
    );
    if !split_after {
        write_hash_record_with_value(&mut extra, encrypted.blake2sp_mac);
    }

    let compression_info =
        u64::from(algorithm_version) | (1 << 7) | solid_compression_flag(solid_continuation);
    let specific = file_specific(
        entry.name,
        entry.data.len() as u64,
        (!split_after).then_some(encrypted.crc32_mac),
        entry.attributes,
        entry.mtime,
        compression_info,
        entry.host_os,
    )?;
    let mut block_flags = HFL_EXTRA | HFL_DATA;
    if split_before {
        block_flags |= HFL_SPLIT_BEFORE;
    }
    if split_after {
        block_flags |= HFL_SPLIT_AFTER;
    }

    if let Some(header_keys) = header_keys {
        out.extend_from_slice(&encrypted_header_block(
            header_keys,
            HEAD_FILE,
            block_flags,
            Some(data.len() as u64),
            &specific,
            &extra,
            data,
        )?);
        Ok(())
    } else {
        write_block(
            out,
            HEAD_FILE,
            block_flags,
            Some(data.len() as u64),
            &specific,
            &extra,
            data,
        )
    }
}

fn write_stored_entry_fragment(
    out: &mut Vec<u8>,
    entry: &StoredEntry<'_>,
    data: &[u8],
    unpacked_size: u64,
    data_crc32: Option<u32>,
    split_before: bool,
    split_after: bool,
) -> Result<()> {
    let mut extra = Vec::new();
    if !split_before && !split_after {
        write_hash_record(&mut extra, data);
    }
    let specific = stored_file_specific(
        entry.name,
        unpacked_size,
        data_crc32,
        entry.attributes,
        entry.mtime,
        entry.host_os,
    )?;
    let mut block_flags = HFL_DATA;
    if split_before {
        block_flags |= HFL_SPLIT_BEFORE;
    }
    if split_after {
        block_flags |= HFL_SPLIT_AFTER;
    }
    if !extra.is_empty() {
        block_flags |= HFL_EXTRA;
    }

    write_block(
        out,
        HEAD_FILE,
        block_flags,
        Some(data.len() as u64),
        &specific,
        &extra,
        data,
    )
}

fn write_stored_service(out: &mut Vec<u8>, name: &[u8], data: &[u8]) -> Result<()> {
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, &[]);
    let specific = stored_file_specific(name, data.len() as u64, Some(crc32(data)), 0, None, 0)?;

    write_block(
        out,
        HEAD_SERVICE,
        HFL_EXTRA | HFL_DATA,
        Some(data.len() as u64),
        &specific,
        &extra,
        data,
    )
}

fn write_recovery_service(out: &mut Vec<u8>, recovery_percent: u64) -> Result<()> {
    let mut service_data = Vec::new();
    write_vint(&mut service_data, recovery_percent);
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, &service_data);

    let data = build_structural_inline_recovery_data(out, recovery_percent)?;
    let specific = stored_file_specific(b"RR", data.len() as u64, Some(crc32(&data)), 0, None, 0)?;
    write_block(
        out,
        HEAD_SERVICE,
        HFL_EXTRA | HFL_DATA,
        Some(data.len() as u64),
        &specific,
        &extra,
        &data,
    )
}

fn write_stored_service_with_cache(
    out: &mut Vec<u8>,
    cached_headers: &mut Vec<CachedHeader>,
    name: &[u8],
    data: &[u8],
) -> Result<()> {
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, &[]);
    let specific = stored_file_specific(name, data.len() as u64, Some(crc32(data)), 0, None, 0)?;

    write_block_with_cache(
        out,
        cached_headers,
        BlockParts {
            header_type: HEAD_SERVICE,
            flags: HFL_EXTRA | HFL_DATA,
            data_size: Some(data.len() as u64),
            type_specific: &specific,
            extra: &extra,
            data,
        },
    )
}

fn write_encrypted_stored_service(
    out: &mut Vec<u8>,
    name: &[u8],
    comment: EncryptedArchiveCommentEntry<'_>,
) -> Result<()> {
    write_encrypted_stored_service_with_header_keys(out, name, comment, None)
}

fn write_encrypted_stored_service_with_header_keys(
    out: &mut Vec<u8>,
    name: &[u8],
    comment: EncryptedArchiveCommentEntry<'_>,
    header_keys: Option<&Rar50Keys>,
) -> Result<()> {
    write_encrypted_service_with_header_keys(
        out,
        name,
        comment.data,
        &[],
        comment.password,
        header_keys,
    )
}

fn write_header_encrypted_recovery_service(
    out: &mut Vec<u8>,
    recovery_percent: u64,
    header_keys: &Rar50Keys,
) -> Result<()> {
    let mut service_data = Vec::new();
    write_vint(&mut service_data, recovery_percent);
    let data = build_structural_inline_recovery_data(out, recovery_percent)?;
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, &service_data);
    let specific = stored_file_specific(b"RR", data.len() as u64, Some(crc32(&data)), 0, None, 0)?;
    out.extend_from_slice(&encrypted_header_block(
        header_keys,
        HEAD_SERVICE,
        HFL_EXTRA | HFL_DATA,
        Some(data.len() as u64),
        &specific,
        &extra,
        &data,
    )?);
    Ok(())
}

fn write_encrypted_service_with_header_keys(
    out: &mut Vec<u8>,
    name: &[u8],
    data: &[u8],
    service_data: &[u8],
    password: &[u8],
    header_keys: Option<&Rar50Keys>,
) -> Result<()> {
    validate_nonempty_password(password)?;
    let encrypted = encrypted_stored_payload(data, password)?;
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, service_data);
    write_file_encryption_record(
        &mut extra,
        encrypted.salt,
        encrypted.iv,
        encrypted.check_value,
    );
    write_hash_record_with_value(&mut extra, encrypted.blake2sp_mac);
    let specific = stored_file_specific(
        name,
        data.len() as u64,
        Some(encrypted.crc32_mac),
        0,
        None,
        0,
    )?;

    if let Some(header_keys) = header_keys {
        out.extend_from_slice(&encrypted_header_block(
            header_keys,
            HEAD_SERVICE,
            HFL_EXTRA | HFL_DATA,
            Some(encrypted.data.len() as u64),
            &specific,
            &extra,
            &encrypted.data,
        )?);
        Ok(())
    } else {
        write_block(
            out,
            HEAD_SERVICE,
            HFL_EXTRA | HFL_DATA,
            Some(encrypted.data.len() as u64),
            &specific,
            &extra,
            &encrypted.data,
        )
    }
}

fn stored_file_specific(
    name: &[u8],
    unpacked_size: u64,
    data_crc32: Option<u32>,
    attributes: u64,
    mtime: Option<u32>,
    host_os: u64,
) -> Result<Vec<u8>> {
    file_specific(
        name,
        unpacked_size,
        data_crc32,
        attributes,
        mtime,
        0,
        host_os,
    )
}

fn file_specific(
    name: &[u8],
    unpacked_size: u64,
    data_crc32: Option<u32>,
    attributes: u64,
    mtime: Option<u32>,
    compression_info: u64,
    host_os: u64,
) -> Result<Vec<u8>> {
    if name.is_empty() {
        return Err(Error::InvalidHeader("RAR 5 file name is empty"));
    }
    let mut file_flags = if data_crc32.is_some() { FHFL_CRC32 } else { 0 };
    if mtime.is_some() {
        file_flags |= FHFL_MTIME;
    }

    let mut specific = Vec::new();
    write_vint(&mut specific, file_flags);
    write_vint(&mut specific, unpacked_size);
    write_vint(&mut specific, attributes);
    if let Some(mtime) = mtime {
        specific.extend_from_slice(&mtime.to_le_bytes());
    }
    if let Some(data_crc32) = data_crc32 {
        specific.extend_from_slice(&data_crc32.to_le_bytes());
    }
    write_vint(&mut specific, compression_info);
    write_vint(&mut specific, host_os);
    write_vint(&mut specific, name.len() as u64);
    specific.extend_from_slice(name);
    Ok(specific)
}

fn validate_entry(entry: &StoredEntry<'_>) -> Result<()> {
    validate_file_entry(entry.name)
}

fn validate_compressed_entry(entry: &CompressedEntry<'_>) -> Result<()> {
    validate_file_entry(entry.name)
}

fn validate_encrypted_entry(entry: &EncryptedStoredEntry<'_>) -> Result<()> {
    validate_file_entry(entry.name)?;
    if entry.password.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted writer needs a non-empty password",
        ));
    }
    Ok(())
}

fn validate_encrypted_compressed_entry(entry: &EncryptedCompressedEntry<'_>) -> Result<()> {
    validate_file_entry(entry.name)?;
    if entry.password.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted writer needs a non-empty password",
        ));
    }
    Ok(())
}

fn validate_file_service(service: &StoredServiceEntry<'_>) -> Result<()> {
    if !matches!(service.name, b"ACL" | b"STM" | b"CMT") {
        return Err(Error::UnsupportedFeature {
            version: crate::ArchiveVersion::Rar50,
            feature: "RAR 5 stored file service name",
        });
    }
    if service.data.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 stored file service data is empty",
        ));
    }
    Ok(())
}

fn validate_encrypted_file_service(service: &EncryptedStoredServiceEntry<'_>) -> Result<()> {
    if !matches!(service.name, b"CMT") {
        return Err(Error::UnsupportedFeature {
            version: crate::ArchiveVersion::Rar50,
            feature: "RAR 5 encrypted stored file service name",
        });
    }
    if service.data.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted stored file service data is empty",
        ));
    }
    validate_nonempty_password(service.password)
}

fn validate_recovery_percent(percent: u64) -> Result<()> {
    if !(1..=100).contains(&percent) {
        return Err(Error::InvalidHeader(
            "RAR 5 recovery percent must be in 1..=100",
        ));
    }
    Ok(())
}

fn validate_nonempty_password(password: &[u8]) -> Result<()> {
    if password.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted writer needs a non-empty password",
        ));
    }
    Ok(())
}

fn validate_file_entry(name: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidHeader("RAR 5 file name is empty"));
    }
    Ok(())
}

fn write_block(
    out: &mut Vec<u8>,
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &[u8],
    extra: &[u8],
    data: &[u8],
) -> Result<()> {
    let header = block_header_image(header_type, flags, data_size, type_specific, extra)?;
    out.extend_from_slice(&header);
    out.extend_from_slice(data);
    Ok(())
}

fn write_block_with_cache(
    out: &mut Vec<u8>,
    cached_headers: &mut Vec<CachedHeader>,
    parts: BlockParts<'_>,
) -> Result<()> {
    let offset = out.len();
    let header = block_header_image(
        parts.header_type,
        parts.flags,
        parts.data_size,
        parts.type_specific,
        parts.extra,
    )?;
    cached_headers.push(CachedHeader {
        offset,
        header: header.clone(),
    });
    out.extend_from_slice(&header);
    out.extend_from_slice(parts.data);
    Ok(())
}

fn quick_open_payload(cached_headers: &[CachedHeader], qo_pos: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for cached in cached_headers {
        let offset = qo_pos
            .checked_sub(cached.offset)
            .ok_or(Error::InvalidHeader(
                "RAR 5 quick-open cached header is after QO header",
            ))?;
        let mut body = Vec::new();
        write_vint(&mut body, 0);
        write_vint(&mut body, offset as u64);
        write_vint(&mut body, cached.header.len() as u64);
        body.extend_from_slice(&cached.header);

        out.extend_from_slice(&crc32(&body).to_le_bytes());
        write_vint(&mut out, body.len() as u64);
        out.extend_from_slice(&body);
    }
    Ok(out)
}

fn encrypted_header_block(
    keys: &Rar50Keys,
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &[u8],
    extra: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    let header = block_header_image(header_type, flags, data_size, type_specific, extra)?;
    let mut iv = [0u8; 16];
    getrandom::getrandom(&mut iv)
        .map_err(|_| Error::InvalidHeader("RAR 5 writer could not generate encryption IV"))?;
    let padded_len = header.len().checked_add(15).ok_or(Error::InvalidHeader(
        "RAR 5 encrypted header size overflows",
    ))? & !15;
    let mut encrypted_header = header;
    encrypted_header.resize(padded_len, 0);
    Rar50Cipher::new(keys.key, iv).encrypt_in_place(&mut encrypted_header);
    let mut out = Vec::with_capacity(16 + encrypted_header.len() + data.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&encrypted_header);
    out.extend_from_slice(data);
    Ok(out)
}

fn block_header_image(
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &[u8],
    extra: &[u8],
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    write_vint(&mut body, header_type);
    write_vint(&mut body, flags);
    if flags & HFL_EXTRA != 0 {
        write_vint(&mut body, extra.len() as u64);
    }
    if let Some(data_size) = data_size {
        write_vint(&mut body, data_size);
    }
    body.extend_from_slice(type_specific);
    body.extend_from_slice(extra);

    let mut header_size = Vec::new();
    write_vint(&mut header_size, body.len() as u64);

    let mut header = Vec::with_capacity(4 + header_size.len() + body.len());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&header_size);
    header.extend_from_slice(&body);
    let header_crc = crc32(&header[4..]);
    header[..4].copy_from_slice(&header_crc.to_le_bytes());
    Ok(header)
}

fn write_extra_record(out: &mut Vec<u8>, record_type: u64, data: &[u8]) {
    let mut body = Vec::new();
    write_vint(&mut body, record_type);
    body.extend_from_slice(data);
    write_vint(out, body.len() as u64);
    out.extend_from_slice(&body);
}

fn write_hash_record(out: &mut Vec<u8>, data: &[u8]) {
    write_hash_record_with_value(out, blake2sp::hash(data));
}

fn write_hash_record_with_value(out: &mut Vec<u8>, hash: [u8; 32]) {
    let mut record = Vec::new();
    write_vint(&mut record, 0);
    record.extend_from_slice(&hash);
    write_extra_record(out, FHEXTRA_HASH, &record);
}

fn write_file_encryption_record(
    out: &mut Vec<u8>,
    salt: [u8; 16],
    iv: [u8; 16],
    check_value: [u8; 12],
) {
    let mut record = Vec::new();
    write_vint(&mut record, 0);
    write_vint(&mut record, 0x0003);
    record.push(0);
    record.extend_from_slice(&salt);
    record.extend_from_slice(&iv);
    record.extend_from_slice(&check_value);
    write_extra_record(out, FHEXTRA_CRYPT, &record);
}

fn map_rar50_crypto_error(error: rars_crypto::rar50::Error) -> Error {
    match error {
        rars_crypto::rar50::Error::KdfCountTooLarge => Error::UnsupportedFeature {
            version: crate::version::ArchiveVersion::Rar50,
            feature: "RAR 5 KDF count",
        },
        rars_crypto::rar50::Error::BadPassword => Error::WrongPasswordOrCorruptData,
    }
}

fn write_vint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rars_codec::rar50::{encode_literal_only, encode_lz_member};
    use std::fs;
    use std::process::Command;

    #[test]
    fn internal_literal_only_compressed_member_round_trips_through_rar50_reader() {
        let data = b"RAR5 literal-only compressed format-layer experiment\n";
        let packed = encode_literal_only(data, 0).unwrap();
        let name = b"compressed.txt";

        let mut archive = Vec::new();
        archive.extend_from_slice(RAR50_SIGNATURE);
        write_main_header(&mut archive, 0, None, &[]).unwrap();

        let mut extra = Vec::new();
        write_hash_record(&mut extra, data);
        let compression_info = 1 << 7; // RAR5 v0, non-solid, method m1, 128 KiB dictionary.
        let specific = file_specific(
            name,
            data.len() as u64,
            Some(crc32(data)),
            0x20,
            None,
            compression_info,
            0,
        )
        .unwrap();
        write_block(
            &mut archive,
            HEAD_FILE,
            HFL_EXTRA | HFL_DATA,
            Some(packed.len() as u64),
            &specific,
            &extra,
            &packed,
        )
        .unwrap();
        write_block(&mut archive, HEAD_END, 0, None, &[], &[], &[]).unwrap();

        let parsed = Archive::parse(&archive).unwrap();
        let file = parsed.files().next().unwrap();
        let info = file.decoded_compression_info().unwrap();
        assert_eq!(info.method, 1);
        assert_eq!(info.dictionary_size, 128 * 1024);

        let extracted = parsed.extract().unwrap();
        assert_eq!(extracted[0].name, name);
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    #[ignore = "requires local rar command; used for reference-validating experimental RAR5 compressed output"]
    fn reference_rar_accepts_internal_literal_only_compressed_member() {
        let data = b"RAR5 literal-only compressed reference experiment\n";
        let packed = encode_literal_only(data, 0).unwrap();
        let name = b"compressed.txt";

        let mut archive = Vec::new();
        archive.extend_from_slice(RAR50_SIGNATURE);
        write_main_header(&mut archive, 0, None, &[]).unwrap();

        let mut extra = Vec::new();
        write_hash_record(&mut extra, data);
        let specific = file_specific(
            name,
            data.len() as u64,
            Some(crc32(data)),
            0x20,
            None,
            1 << 7,
            0,
        )
        .unwrap();
        write_block(
            &mut archive,
            HEAD_FILE,
            HFL_EXTRA | HFL_DATA,
            Some(packed.len() as u64),
            &specific,
            &extra,
            &packed,
        )
        .unwrap();
        write_block(&mut archive, HEAD_END, 0, None, &[], &[], &[]).unwrap();

        let mut path = std::env::temp_dir();
        path.push(format!(
            "rars-rar50-literal-only-{}.rar",
            std::process::id()
        ));
        fs::write(&path, archive).unwrap();
        let output = match Command::new("rar").arg("t").arg(&path).output() {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("failed to run rar: {error}"),
        };
        if std::env::var_os("RARS_KEEP_REFERENCE_ARCHIVE").is_none() {
            let _ = fs::remove_file(&path);
        }

        assert!(
            output.status.success(),
            "rar rejected experimental RAR5 compressed output\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "requires local rar command; used for reference-validating experimental RAR5 match output"]
    fn reference_rar_accepts_internal_match_compressed_member() {
        let data = b"RAR5 match compressed reference experiment\n".repeat(8);
        let packed = encode_lz_member(&data, 0).unwrap();
        let name = b"compressed.txt";

        let mut archive = Vec::new();
        archive.extend_from_slice(RAR50_SIGNATURE);
        write_main_header(&mut archive, 0, None, &[]).unwrap();

        let mut extra = Vec::new();
        write_hash_record(&mut extra, &data);
        let specific = file_specific(
            name,
            data.len() as u64,
            Some(crc32(&data)),
            0x20,
            None,
            1 << 7,
            0,
        )
        .unwrap();
        write_block(
            &mut archive,
            HEAD_FILE,
            HFL_EXTRA | HFL_DATA,
            Some(packed.len() as u64),
            &specific,
            &extra,
            &packed,
        )
        .unwrap();
        write_block(&mut archive, HEAD_END, 0, None, &[], &[], &[]).unwrap();

        let mut path = std::env::temp_dir();
        path.push(format!("rars-rar50-match-{}.rar", std::process::id()));
        fs::write(&path, archive).unwrap();
        let output = match Command::new("rar").arg("t").arg(&path).output() {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("failed to run rar: {error}"),
        };
        if std::env::var_os("RARS_KEEP_REFERENCE_ARCHIVE").is_none() {
            let _ = fs::remove_file(&path);
        }

        assert!(
            output.status.success(),
            "rar rejected experimental RAR5 match output\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
