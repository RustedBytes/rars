use crate::detect::{find_archive_start, RAR13_SIGNATURE};
use crate::error::{Error, Result};
use crate::features::FeatureSet;
use crate::version::{ArchiveFamily, ArchiveVersion};

const MAIN_HEAD_SIZE: u16 = 7;
const FILE_HEAD_BASE_SIZE: usize = 21;
const MHD_VOLUME: u8 = 0x01;
const MHD_COMMENT: u8 = 0x02;
const MHD_SOLID: u8 = 0x08;
const MHD_PACK_COMMENT: u8 = 0x10;
const MHD_AV: u8 = 0x20;
const MHD_ALWAYS_SET: u8 = 0x80;
const RAR13_AV_PREFIX: &[u8; 6] = b"\x1ai\x6d\x02\xda\xae";
const LHD_SPLIT_BEFORE: u8 = 0x01;
const LHD_SPLIT_AFTER: u8 = 0x02;
const LHD_PASSWORD: u8 = 0x04;
const LHD_COMMENT: u8 = 0x08;
const LHD_SOLID: u8 = 0x10;
const METHOD_STORE: u8 = 0;
const DEFAULT_UNP_VER: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainHeader {
    pub flags: u8,
    pub head_size: u16,
    pub extra: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub flags: u8,
    pub pack_size: u32,
    pub unp_size: u32,
    pub file_crc: u16,
    pub file_time: u32,
    pub file_attr: u8,
    pub unp_ver: u8,
    pub method: u8,
    pub head_size: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub header: FileHeader,
    pub name: Vec<u8>,
    pub extra: Vec<u8>,
    pub packed_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Archive {
    pub sfx_offset: usize,
    pub main: MainHeader,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticityVerification {
    pub size: u16,
    pub prefix: [u8; 6],
    pub cipher_body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticityVerificationStatus {
    Absent,
    StructurallyValid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedEntry {
    pub name: Vec<u8>,
    pub data: Vec<u8>,
    pub file_time: u32,
    pub file_attr: u8,
    pub is_directory: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterOptions {
    pub target: ArchiveVersion,
    pub features: FeatureSet,
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            target: ArchiveVersion::Rar14,
            features: FeatureSet::store_only(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub file_time: u32,
    pub file_attr: u8,
    pub password: Option<&'a [u8]>,
    pub file_comment: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub file_time: u32,
    pub file_attr: u8,
    pub password: Option<&'a [u8]>,
    pub file_comment: Option<&'a [u8]>,
}

impl MainHeader {
    pub fn is_volume(&self) -> bool {
        self.flags & MHD_VOLUME != 0
    }

    pub fn has_archive_comment(&self) -> bool {
        self.flags & MHD_COMMENT != 0
    }

    pub fn has_packed_comment(&self) -> bool {
        self.flags & MHD_PACK_COMMENT != 0
    }

    pub fn is_solid(&self) -> bool {
        self.flags & MHD_SOLID != 0
    }

    pub fn has_authenticity_verification(&self) -> bool {
        self.flags & MHD_AV != 0
    }

    fn parse(input: &[u8]) -> Result<Self> {
        if input.len() < MAIN_HEAD_SIZE as usize {
            return Err(Error::TooShort);
        }
        if !input.starts_with(RAR13_SIGNATURE) {
            return Err(Error::UnsupportedSignature);
        }

        let head_size = read_u16(input, 4)?;
        let flags = input[6];
        if head_size < MAIN_HEAD_SIZE {
            return Err(Error::InvalidHeader(
                "RAR 1.3 main header is shorter than 7 bytes",
            ));
        }
        if head_size as usize > input.len() {
            return Err(Error::TooShort);
        }

        let extra = input[MAIN_HEAD_SIZE as usize..head_size as usize].to_vec();

        Ok(Self {
            flags,
            head_size,
            extra,
        })
    }
}

impl FileHeader {
    fn parse(input: &[u8]) -> Result<(Self, Vec<u8>, Vec<u8>, usize)> {
        if input.len() < FILE_HEAD_BASE_SIZE {
            return Err(Error::TooShort);
        }

        let pack_size = read_u32(input, 0)?;
        let unp_size = read_u32(input, 4)?;
        let file_crc = read_u16(input, 8)?;
        let head_size = read_u16(input, 10)?;
        let file_time = read_u32(input, 12)?;
        let file_attr = input[16];
        let flags = input[17];
        let unp_ver = input[18];
        let name_size = input[19] as usize;
        let method = input[20];
        let minimum_size = FILE_HEAD_BASE_SIZE + name_size;

        if (head_size as usize) < minimum_size {
            return Err(Error::InvalidHeader(
                "RAR 1.3 file header is shorter than its name",
            ));
        }
        if input.len() < head_size as usize {
            return Err(Error::TooShort);
        }

        let name = input[FILE_HEAD_BASE_SIZE..FILE_HEAD_BASE_SIZE + name_size].to_vec();
        let extra = input[minimum_size..head_size as usize].to_vec();
        Ok((
            Self {
                flags,
                pack_size,
                unp_size,
                file_crc,
                file_time,
                file_attr,
                unp_ver,
                method,
                head_size,
            },
            name,
            extra,
            head_size as usize,
        ))
    }
}

impl Archive {
    pub fn parse(input: &[u8]) -> Result<Self> {
        let sig = find_archive_start(input, 128 * 1024).ok_or(Error::UnsupportedSignature)?;
        if sig.family != ArchiveFamily::Rar13 {
            return Err(Error::UnsupportedSignature);
        }

        let archive = &input[sig.offset..];
        let main = MainHeader::parse(archive)?;
        let mut pos = main.head_size as usize;
        let mut entries = Vec::new();

        while pos < archive.len() {
            if archive.len() - pos < FILE_HEAD_BASE_SIZE {
                break;
            }

            let (header, name, extra, consumed) = FileHeader::parse(&archive[pos..])?;
            let data_start = pos + consumed;
            let data_end =
                data_start
                    .checked_add(header.pack_size as usize)
                    .ok_or(Error::InvalidHeader(
                        "RAR 1.3 file data size overflows usize",
                    ))?;
            if data_end > archive.len() {
                return Err(Error::TooShort);
            }

            entries.push(Entry {
                header,
                name,
                extra,
                packed_data: archive[data_start..data_end].to_vec(),
            });
            pos = data_end;
        }

        Ok(Self {
            sfx_offset: sig.offset,
            main,
            entries,
        })
    }

    pub fn extract_stored(&self, password: Option<&[u8]>) -> Result<Vec<ExtractedEntry>> {
        let mut out = Vec::new();
        for entry in &self.entries {
            if entry.is_split_before() || entry.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 1.3 split entry requires multivolume extraction",
                ));
            }
            out.push(entry.extract_stored(password)?);
        }
        Ok(out)
    }

    pub fn extract(&self, password: Option<&[u8]>) -> Result<Vec<ExtractedEntry>> {
        let mut out = Vec::new();
        let mut unpack15 = Unpack15::new();
        for entry in &self.entries {
            if entry.is_split_before() || entry.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 1.3 split entry requires multivolume extraction",
                ));
            }
            out.push(entry.extract_with_context(
                password,
                Some(&mut unpack15),
                self.main.is_solid() && !out.is_empty(),
            )?);
        }
        Ok(out)
    }

    pub fn archive_comment(&self) -> Result<Option<Vec<u8>>> {
        if !self.main.has_archive_comment() {
            return Ok(None);
        }

        let length = read_u16(&self.main.extra, 0)? as usize;
        if self.main.has_packed_comment() {
            if length < 2 {
                return Err(Error::InvalidHeader(
                    "RAR 1.3 packed archive comment is shorter than size field",
                ));
            }
            let unpacked_len = read_u16(&self.main.extra, 2)? as usize;
            let packed_len = length - 2;
            let packed_start = 4usize;
            let packed_end = packed_start
                .checked_add(packed_len)
                .ok_or(Error::InvalidHeader(
                    "RAR 1.3 archive comment size overflows",
                ))?;
            if packed_end > self.main.extra.len() {
                return Err(Error::TooShort);
            }

            let mut packed = self.main.extra[packed_start..packed_end].to_vec();
            Rar13Cipher::new_comment().decrypt_in_place(&mut packed);
            return Ok(Some(unpack15_decode(&packed, unpacked_len)?));
        }

        let comment_start = 2usize;
        let comment_end = comment_start
            .checked_add(length)
            .ok_or(Error::InvalidHeader(
                "RAR 1.3 archive comment size overflows",
            ))?;
        if comment_end > self.main.extra.len() {
            return Err(Error::TooShort);
        }
        Ok(Some(self.main.extra[comment_start..comment_end].to_vec()))
    }

    pub fn authenticity_verification(&self) -> Result<Option<AuthenticityVerification>> {
        if !self.main.has_authenticity_verification() {
            return Ok(None);
        }
        let size = read_u16(&self.main.extra, 0)?;
        if size < RAR13_AV_PREFIX.len() as u16 {
            return Err(Error::InvalidHeader("RAR 1.3 AV payload is too short"));
        }
        let payload_end = 2usize
            .checked_add(size as usize)
            .ok_or(Error::InvalidHeader("RAR 1.3 AV payload size overflows"))?;
        if payload_end > self.main.extra.len() {
            return Err(Error::TooShort);
        }
        let prefix_bytes = self
            .main
            .extra
            .get(2..2 + RAR13_AV_PREFIX.len())
            .ok_or(Error::TooShort)?;
        let prefix: [u8; 6] = prefix_bytes
            .try_into()
            .expect("RAR 1.3 AV prefix slice has fixed length");
        if &prefix != RAR13_AV_PREFIX {
            return Err(Error::InvalidHeader("RAR 1.3 AV prefix mismatch"));
        }
        Ok(Some(AuthenticityVerification {
            size,
            prefix,
            cipher_body: self.main.extra[2 + RAR13_AV_PREFIX.len()..payload_end].to_vec(),
        }))
    }

    pub fn verify_authenticity_verification(&self) -> Result<AuthenticityVerificationStatus> {
        Ok(if self.authenticity_verification()?.is_some() {
            AuthenticityVerificationStatus::StructurallyValid
        } else {
            AuthenticityVerificationStatus::Absent
        })
    }
}

impl Entry {
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }

    pub fn is_encrypted(&self) -> bool {
        self.header.flags & LHD_PASSWORD != 0
    }

    pub fn is_split_before(&self) -> bool {
        self.header.flags & LHD_SPLIT_BEFORE != 0
    }

    pub fn is_split_after(&self) -> bool {
        self.header.flags & LHD_SPLIT_AFTER != 0
    }

    pub fn is_directory(&self) -> bool {
        self.header.file_attr & 0x10 != 0
    }

    pub fn has_file_comment(&self) -> bool {
        self.header.flags & LHD_COMMENT != 0
    }

    pub fn file_comment(&self) -> Result<Option<Vec<u8>>> {
        if !self.has_file_comment() {
            return Ok(None);
        }
        let length = read_u16(&self.extra, 0)? as usize;
        let comment_start = 2usize;
        let comment_end = comment_start
            .checked_add(length)
            .ok_or(Error::InvalidHeader("RAR 1.3 file comment size overflows"))?;
        if comment_end > self.extra.len() {
            return Err(Error::TooShort);
        }
        Ok(Some(self.extra[comment_start..comment_end].to_vec()))
    }

    pub fn is_stored(&self) -> bool {
        self.header.method == METHOD_STORE
    }

    pub fn stored_data(&self, password: Option<&[u8]>) -> Result<Vec<u8>> {
        if !self.is_stored() {
            return Err(Error::InvalidHeader("RAR 1.3 entry is not stored"));
        }

        self.decrypt_packed_data(password)
    }

    fn decrypt_packed_data(&self, password: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut data = self.packed_data.clone();
        if self.is_encrypted() {
            let password = password.ok_or(Error::NeedPassword)?;
            Rar13Cipher::new(password).decrypt_in_place(&mut data);
        }

        Ok(data)
    }

    pub fn verify_checksum(&self, data: &[u8]) -> Result<()> {
        let actual = file_checksum(data);
        if actual == self.header.file_crc {
            Ok(())
        } else {
            Err(Error::CrcMismatch {
                expected: self.header.file_crc,
                actual,
            })
        }
    }

    pub fn extract_stored(&self, password: Option<&[u8]>) -> Result<ExtractedEntry> {
        if self.is_directory() {
            return Ok(ExtractedEntry {
                name: self.name.clone(),
                data: Vec::new(),
                file_time: self.header.file_time,
                file_attr: self.header.file_attr,
                is_directory: true,
            });
        }

        let data = self.stored_data(password)?;
        self.verify_checksum(&data)?;
        Ok(ExtractedEntry {
            name: self.name.clone(),
            data,
            file_time: self.header.file_time,
            file_attr: self.header.file_attr,
            is_directory: self.is_directory(),
        })
    }

    pub fn extract(&self, password: Option<&[u8]>) -> Result<ExtractedEntry> {
        self.extract_with_context(password, None, false)
    }

    fn extract_with_context(
        &self,
        password: Option<&[u8]>,
        unpack15: Option<&mut Unpack15>,
        solid: bool,
    ) -> Result<ExtractedEntry> {
        if self.is_stored() || self.is_directory() {
            return self.extract_stored(password);
        }

        let packed = self.decrypt_packed_data(password)?;
        let data = if let Some(unpack15) = unpack15 {
            unpack15.decode_member(&packed, self.header.unp_size as usize, solid)?
        } else {
            unpack15_decode(&packed, self.header.unp_size as usize)?
        };
        self.verify_checksum(&data)?;
        Ok(ExtractedEntry {
            name: self.name.clone(),
            data,
            file_time: self.header.file_time,
            file_attr: self.header.file_attr,
            is_directory: false,
        })
    }
}

pub fn extract_volumes(
    volumes: &[Archive],
    password: Option<&[u8]>,
) -> Result<Vec<ExtractedEntry>> {
    let mut out = Vec::new();
    let mut pending: Option<PendingSplit> = None;
    let mut unpack15 = Unpack15::new();

    for archive in volumes {
        for entry in &archive.entries {
            if !entry.is_split_before() && !entry.is_split_after() {
                if pending.is_some() {
                    return Err(Error::InvalidHeader(
                        "RAR 1.3 split entry is interrupted by a regular entry",
                    ));
                }
                let solid = archive.main.is_solid() && !out.is_empty();
                out.push(entry.extract_with_context(password, Some(&mut unpack15), solid)?);
                continue;
            }

            let data = entry.decrypt_packed_data(password)?;
            match (
                &mut pending,
                entry.is_split_before(),
                entry.is_split_after(),
            ) {
                (None, false, true) => {
                    pending = Some(PendingSplit::new(entry, data));
                }
                (Some(current), true, true) => {
                    current.append(entry, data)?;
                }
                (Some(current), true, false) => {
                    current.append(entry, data)?;
                    let completed = pending.take().expect("pending split");
                    let solid = archive.main.is_solid() && !out.is_empty();
                    out.push(completed.finish(entry, &mut unpack15, solid)?);
                }
                _ => {
                    return Err(Error::InvalidHeader(
                        "RAR 1.3 split entry flags are inconsistent",
                    ));
                }
            }
        }
    }

    if pending.is_some() {
        return Err(Error::InvalidHeader("RAR 1.3 split entry is incomplete"));
    }

    Ok(out)
}

pub fn extract_stored_volumes(
    volumes: &[Archive],
    password: Option<&[u8]>,
) -> Result<Vec<ExtractedEntry>> {
    extract_volumes(volumes, password)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingSplit {
    name: Vec<u8>,
    packed_data: Vec<u8>,
    file_time: u32,
    file_attr: u8,
    method: u8,
    unp_ver: u8,
    was_encrypted: bool,
}

impl PendingSplit {
    fn new(entry: &Entry, packed_data: Vec<u8>) -> Self {
        Self {
            name: entry.name.clone(),
            packed_data,
            file_time: entry.header.file_time,
            file_attr: entry.header.file_attr,
            method: entry.header.method,
            unp_ver: entry.header.unp_ver,
            was_encrypted: entry.is_encrypted(),
        }
    }

    fn append(&mut self, entry: &Entry, packed_data: Vec<u8>) -> Result<()> {
        if entry.name != self.name {
            return Err(Error::InvalidHeader("RAR 1.3 split entry name changed"));
        }
        if entry.header.method != self.method {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry compression method changed",
            ));
        }
        if entry.is_encrypted() != self.was_encrypted {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry encryption flag changed",
            ));
        }
        self.packed_data.extend_from_slice(&packed_data);
        Ok(())
    }

    fn finish(
        self,
        final_entry: &Entry,
        unpack15: &mut Unpack15,
        solid: bool,
    ) -> Result<ExtractedEntry> {
        let combined = Entry {
            header: FileHeader {
                flags: final_entry.header.flags
                    & !(LHD_SPLIT_BEFORE | LHD_SPLIT_AFTER | LHD_PASSWORD),
                pack_size: self.packed_data.len() as u32,
                unp_size: final_entry.header.unp_size,
                file_crc: final_entry.header.file_crc,
                file_time: self.file_time,
                file_attr: self.file_attr,
                unp_ver: self.unp_ver,
                method: self.method,
                head_size: final_entry.header.head_size,
            },
            name: self.name,
            extra: Vec::new(),
            packed_data: self.packed_data,
        };
        combined.extract_with_context(None, Some(unpack15), solid)
    }
}

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
    if !options.target.is_rar13_family() {
        return Err(Error::UnsupportedVersion(options.target));
    }
    options.features.validate_for(options.target)?;
    validate_stored_writer_features(options.target, options.features)?;

    let mut out = Vec::new();
    write_main_header(&mut out, options.features, archive_comment)?;

    for entry in entries {
        validate_stored_entry(entry)?;
        write_stored_entry(&mut out, entry, options.features)?;
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
    if !options.target.is_rar13_family() {
        return Err(Error::UnsupportedVersion(options.target));
    }
    options.features.validate_for(options.target)?;
    validate_compressed_writer_features(options.target, options.features)?;

    let mut out = Vec::new();
    write_main_header(&mut out, options.features, archive_comment)?;

    let mut solid_encoder = options.features.solid.then(Unpack15Encoder::new);

    for entry in entries {
        validate_file_entry(entry.name, entry.data)?;
        let mut packed = if let Some(encoder) = solid_encoder.as_mut() {
            encoder.encode_member(entry.data)?
        } else {
            unpack15_encode(entry.data)?
        };
        if let Some(password) = entry.password {
            Rar13Cipher::new(password).encrypt_in_place(&mut packed);
        }
        let mut flags = 0;
        if options.features.solid {
            flags |= LHD_SOLID;
        }
        if entry.password.is_some() {
            flags |= LHD_PASSWORD;
        }
        if entry.file_comment.is_some() {
            flags |= LHD_COMMENT;
        }
        let file_extra = encode_file_comment(entry.file_comment)?;
        write_file_entry(
            &mut out,
            entry.name,
            entry.data,
            &packed,
            entry.file_time,
            entry.file_attr,
            flags,
            DEFAULT_UNP_VER,
            3,
            &file_extra,
        )?;
    }

    Ok(out)
}

pub fn write_stored_volumes(
    entry: StoredEntry<'_>,
    options: WriterOptions,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    if !options.target.is_rar13_family() {
        return Err(Error::UnsupportedVersion(options.target));
    }
    options.features.validate_for(options.target)?;
    validate_stored_writer_features(options.target, options.features)?;
    validate_volume_writer_inputs(
        entry.name,
        entry.data,
        entry.password,
        entry.file_comment,
        options,
    )?;

    let body = entry.data.to_vec();
    write_split_volumes(
        entry.name,
        entry.data,
        &body,
        entry.file_time,
        entry.file_attr,
        METHOD_STORE,
        0,
        options.features,
        max_packed_per_volume,
    )
}

pub fn write_compressed_volumes(
    entry: FileEntry<'_>,
    options: WriterOptions,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    if !options.target.is_rar13_family() {
        return Err(Error::UnsupportedVersion(options.target));
    }
    options.features.validate_for(options.target)?;
    validate_compressed_writer_features(options.target, options.features)?;
    validate_volume_writer_inputs(
        entry.name,
        entry.data,
        entry.password,
        entry.file_comment,
        options,
    )?;

    let packed = unpack15_encode(entry.data)?;
    write_split_volumes(
        entry.name,
        entry.data,
        &packed,
        entry.file_time,
        entry.file_attr,
        3,
        0,
        options.features,
        max_packed_per_volume,
    )
}

fn validate_stored_writer_features(version: ArchiveVersion, features: FeatureSet) -> Result<()> {
    reject_writer_feature(version, features.sfx, "sfx")?;
    reject_writer_feature(
        version,
        features.authenticity_verification,
        "authenticity_verification",
    )?;
    Ok(())
}

fn validate_volume_writer_inputs(
    name: &[u8],
    data: &[u8],
    password: Option<&[u8]>,
    file_comment: Option<&[u8]>,
    options: WriterOptions,
) -> Result<()> {
    validate_file_entry(name, data)?;
    if password.is_some() {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "volume_password",
        });
    }
    if file_comment.is_some() || options.features.file_comment {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "volume_file_comment",
        });
    }
    if options.features.archive_comment {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "volume_archive_comment",
        });
    }
    Ok(())
}

fn validate_compressed_writer_features(
    version: ArchiveVersion,
    features: FeatureSet,
) -> Result<()> {
    reject_writer_feature(version, features.sfx, "sfx")?;
    reject_writer_feature(
        version,
        features.authenticity_verification,
        "authenticity_verification",
    )?;
    Ok(())
}

fn reject_writer_feature(
    version: ArchiveVersion,
    enabled: bool,
    feature: &'static str,
) -> Result<()> {
    if enabled {
        Err(Error::UnsupportedFeature { version, feature })
    } else {
        Ok(())
    }
}

fn write_main_header(
    out: &mut Vec<u8>,
    features: FeatureSet,
    archive_comment: Option<&[u8]>,
) -> Result<()> {
    write_main_header_with_flags(out, features, archive_comment, 0)
}

fn write_main_header_with_flags(
    out: &mut Vec<u8>,
    features: FeatureSet,
    archive_comment: Option<&[u8]>,
    extra_flags: u8,
) -> Result<()> {
    let comment_extra = encode_archive_comment(archive_comment)?;
    let mut flags = MHD_ALWAYS_SET | extra_flags;
    if archive_comment.is_some() {
        flags |= MHD_COMMENT;
        flags |= MHD_PACK_COMMENT;
    }
    if features.solid {
        flags |= MHD_SOLID;
    }
    out.extend_from_slice(RAR13_SIGNATURE);
    let head_size = MAIN_HEAD_SIZE as usize + comment_extra.len();
    if head_size > u16::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 main header comment extension is too large",
        ));
    }
    out.extend_from_slice(&(head_size as u16).to_le_bytes());
    out.push(flags);
    out.extend_from_slice(&comment_extra);
    Ok(())
}

fn write_stored_entry(
    out: &mut Vec<u8>,
    entry: &StoredEntry<'_>,
    features: FeatureSet,
) -> Result<()> {
    let mut flags = 0u8;
    if entry.password.is_some() {
        flags |= LHD_PASSWORD;
    }
    if entry.file_comment.is_some() {
        flags |= LHD_COMMENT;
    }
    if features.solid {
        flags |= LHD_SOLID;
    }

    let mut body = entry.data.to_vec();
    if let Some(password) = entry.password {
        Rar13Cipher::new(password).encrypt_in_place(&mut body);
    }

    let file_extra = encode_file_comment(entry.file_comment)?;
    write_file_entry(
        out,
        entry.name,
        entry.data,
        &body,
        entry.file_time,
        entry.file_attr,
        flags,
        DEFAULT_UNP_VER,
        METHOD_STORE,
        &file_extra,
    )?;
    Ok(())
}

fn validate_stored_entry(entry: &StoredEntry<'_>) -> Result<()> {
    validate_file_entry(entry.name, entry.data)
}

fn write_file_entry(
    out: &mut Vec<u8>,
    name: &[u8],
    unpacked: &[u8],
    packed: &[u8],
    file_time: u32,
    file_attr: u8,
    flags: u8,
    unp_ver: u8,
    method: u8,
    extra: &[u8],
) -> Result<()> {
    write_file_entry_with_crc(
        out,
        name,
        unpacked.len() as u32,
        file_checksum(unpacked),
        packed,
        file_time,
        file_attr,
        flags,
        unp_ver,
        method,
        extra,
    )
}

fn write_file_entry_with_crc(
    out: &mut Vec<u8>,
    name: &[u8],
    unpacked_size: u32,
    file_crc: u16,
    packed: &[u8],
    file_time: u32,
    file_attr: u8,
    flags: u8,
    unp_ver: u8,
    method: u8,
    extra: &[u8],
) -> Result<()> {
    let head_size = FILE_HEAD_BASE_SIZE + name.len() + extra.len();
    out.extend_from_slice(&(packed.len() as u32).to_le_bytes());
    out.extend_from_slice(&unpacked_size.to_le_bytes());
    out.extend_from_slice(&file_crc.to_le_bytes());
    out.extend_from_slice(&(head_size as u16).to_le_bytes());
    out.extend_from_slice(&file_time.to_le_bytes());
    out.push(file_attr);
    out.push(flags);
    out.push(unp_ver);
    out.push(name.len() as u8);
    out.push(method);
    out.extend_from_slice(name);
    out.extend_from_slice(extra);
    out.extend_from_slice(packed);
    Ok(())
}

fn write_split_volumes(
    name: &[u8],
    unpacked: &[u8],
    packed: &[u8],
    file_time: u32,
    file_attr: u8,
    method: u8,
    base_flags: u8,
    features: FeatureSet,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    if max_packed_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 1.3 volume payload size must be non-zero",
        ));
    }
    if packed.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 1.3 volume writer needs a non-empty packed payload",
        ));
    }

    let chunks: Vec<&[u8]> = packed.chunks(max_packed_per_volume).collect();
    if chunks.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 1.3 volume writer needs at least two volumes",
        ));
    }

    let mut volumes = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.iter().enumerate() {
        let split_before = index > 0;
        let split_after = index + 1 < chunks.len();
        let mut flags = base_flags;
        if split_before {
            flags |= LHD_SPLIT_BEFORE;
        }
        if split_after {
            flags |= LHD_SPLIT_AFTER;
        }
        if features.solid {
            flags |= LHD_SOLID;
        }

        let mut out = Vec::new();
        write_main_header_with_flags(&mut out, features, None, MHD_VOLUME)?;
        let checksum_data = if split_after { *chunk } else { unpacked };
        write_file_entry_with_crc(
            &mut out,
            name,
            unpacked.len() as u32,
            file_checksum(checksum_data),
            chunk,
            file_time,
            file_attr,
            flags,
            DEFAULT_UNP_VER,
            method,
            &[],
        )?;
        volumes.push(out);
    }

    Ok(volumes)
}

fn encode_archive_comment(comment: Option<&[u8]>) -> Result<Vec<u8>> {
    let Some(comment) = comment else {
        return Ok(Vec::new());
    };
    if comment.len() > u16::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 archive comment is longer than 65535 bytes",
        ));
    }
    let mut packed = unpack15_encode(comment)?;
    Rar13Cipher::new_comment().encrypt_in_place(&mut packed);
    let packed_field_len = packed.len().checked_add(2).ok_or(Error::InvalidHeader(
        "RAR 1.3 archive comment size overflows",
    ))?;
    if packed_field_len > u16::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 packed archive comment is longer than 65535 bytes",
        ));
    }

    let mut out = Vec::with_capacity(4 + packed.len());
    out.extend_from_slice(&(packed_field_len as u16).to_le_bytes());
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(&packed);
    Ok(out)
}

fn encode_file_comment(comment: Option<&[u8]>) -> Result<Vec<u8>> {
    let Some(comment) = comment else {
        return Ok(Vec::new());
    };
    if comment.len() > u16::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 file comment is longer than 65535 bytes",
        ));
    }
    let mut out = Vec::with_capacity(2 + comment.len());
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(comment);
    Ok(out)
}

fn validate_file_entry(name: &[u8], data: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidHeader("RAR 1.3 file name is empty"));
    }
    if name.len() > u8::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 file name is longer than 255 bytes",
        ));
    }
    if data.len() > u32::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 file is larger than 32-bit size fields",
        ));
    }
    Ok(())
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16> {
    let bytes = input.get(offset..offset + 2).ok_or(Error::TooShort)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32> {
    let bytes = input.get(offset..offset + 4).ok_or(Error::TooShort)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub fn file_checksum(input: &[u8]) -> u16 {
    let mut checksum = 0u16;
    for &byte in input {
        checksum = checksum.wrapping_add(byte as u16).rotate_left(1);
    }
    checksum
}

const DEC_L1: &[u16] = &[
    0x8000, 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf200, 0xffff,
];
const POS_L1: &[u16] = &[0, 0, 0, 2, 3, 5, 7, 11, 16, 20, 24, 32, 32];
const DEC_L2: &[u16] = &[
    0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf240, 0xffff,
];
const POS_L2: &[u16] = &[0, 0, 0, 0, 5, 7, 9, 13, 18, 22, 26, 34, 36];
const DEC_HF0: &[u16] = &[
    0x8000, 0xc000, 0xe000, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xffff,
];
const POS_HF0: &[u16] = &[0, 0, 0, 0, 0, 8, 16, 24, 33, 33, 33, 33, 33];
const DEC_HF1: &[u16] = &[
    0x2000, 0xc000, 0xe000, 0xf000, 0xf200, 0xf200, 0xf7e0, 0xffff,
];
const POS_HF1: &[u16] = &[0, 0, 0, 0, 0, 0, 4, 44, 60, 76, 80, 80, 127];
const DEC_HF2: &[u16] = &[
    0x1000, 0x2400, 0x8000, 0xc000, 0xfa00, 0xffff, 0xffff, 0xffff,
];
const POS_HF2: &[u16] = &[0, 0, 0, 0, 0, 0, 2, 7, 53, 117, 233, 0, 0];
const DEC_HF3: &[u16] = &[0x0800, 0x2400, 0xee00, 0xfe80, 0xffff, 0xffff, 0xffff];
const POS_HF3: &[u16] = &[0, 0, 0, 0, 0, 0, 0, 2, 16, 218, 251, 0, 0];
const DEC_HF4: &[u16] = &[0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff];
const POS_HF4: &[u16] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0];

const SHORT_LEN1: [u8; 16] = [1, 3, 4, 4, 5, 6, 7, 8, 8, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR1: [u8; 15] = [
    0x00, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0,
];
const SHORT_LEN2: [u8; 16] = [2, 3, 3, 3, 4, 4, 5, 6, 6, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR2: [u8; 15] = [
    0x00, 0x40, 0x60, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0,
];

fn unpack15_encode(input: &[u8]) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut encoder = Unpack15Encoder::new();
    encoder.encode_member(input)
}

fn unpack15_decode(input: &[u8], output_size: usize) -> Result<Vec<u8>> {
    let mut decoder = Unpack15::new();
    decoder.decode_member(input, output_size, false)
}

struct Unpack15Encoder {
    bits: BitWriter,
    ch_set: [u16; 256],
    ch_set_c: [u16; 256],
    ch_set_b: [u16; 256],
    n_to_pl: [u8; 256],
    n_to_pl_b: [u8; 256],
    n_to_pl_c: [u8; 256],
    ch_set_a: [u16; 256],
    avr_plc: u32,
    avr_plc_b: u32,
    avr_ln1: u32,
    avr_ln2: u32,
    avr_ln3: u32,
    max_dist3: u32,
    nhfb: u32,
    nlzb: u32,
    num_huf: u32,
    old_dist: [u32; 4],
    old_dist_ptr: usize,
    last_dist: u32,
    last_length: u32,
}

impl Unpack15Encoder {
    fn new() -> Self {
        let mut encoder = Self {
            bits: BitWriter::new(),
            ch_set: [0; 256],
            ch_set_c: [0; 256],
            ch_set_b: [0; 256],
            n_to_pl: [0; 256],
            n_to_pl_b: [0; 256],
            n_to_pl_c: [0; 256],
            ch_set_a: [0; 256],
            avr_plc: 0x3500,
            avr_plc_b: 0,
            avr_ln1: 0,
            avr_ln2: 0,
            avr_ln3: 0,
            max_dist3: 0x2001,
            nhfb: 0x80,
            nlzb: 0x80,
            num_huf: 0,
            old_dist: [u32::MAX; 4],
            old_dist_ptr: 0,
            last_dist: u32::MAX,
            last_length: 0,
        };
        encoder.init_huff();
        encoder
    }

    #[cfg(test)]
    fn encode_literals_only(mut self, input: &[u8]) -> Result<Vec<u8>> {
        self.encode_literals_only_member(input)
    }

    #[cfg(test)]
    fn encode_literals_only_member(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(Vec::new());
        }
        self.bits = BitWriter::new();
        let mut pos = 0usize;
        while pos < input.len() {
            let mut flags = 0u8;
            let mut flag_bits = 0usize;
            let mut payloads = Vec::new();
            let mut plan_nhfb = self.nhfb;
            let mut plan_nlzb = self.nlzb;

            while flag_bits < 8 && pos < input.len() {
                let flag = huff_flag_bits(plan_nlzb <= plan_nhfb);
                if flag_bits + flag.len() > 8 {
                    break;
                }
                write_planned_flag_bits(&mut flags, flag_bits, flag);
                payloads.push(EncodedToken::Literal(input[pos]));
                flag_bits += flag.len();
                pos += 1;
                plan_huff_effect(&mut plan_nhfb, &mut plan_nlzb);
            }

            self.emit_flags_byte(flags)?;
            self.emit_payloads(payloads, pos < input.len())?;
        }
        Ok(std::mem::take(&mut self.bits).finish())
    }

    fn encode_member(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(Vec::new());
        }
        self.bits = BitWriter::new();
        let mut pos = 0usize;
        while pos < input.len() {
            let mut flags = 0u8;
            let mut flag_bits = 0usize;
            let mut payloads = Vec::new();
            let mut plan_nhfb = self.nhfb;
            let mut plan_nlzb = self.nlzb;

            while flag_bits < 8 && pos < input.len() {
                if let Some(short_lz) = find_short_lz(input, pos) {
                    if flag_bits + 2 <= 8 {
                        payloads.push(EncodedToken::ShortLz(short_lz));
                        flag_bits += 2;
                        pos += short_lz.length as usize;
                        continue;
                    }
                }
                if let Some(long_lz) = find_long_lz(input, pos) {
                    let flag = long_lz_flag_bits(plan_nlzb > plan_nhfb);
                    if flag_bits + flag.len() <= 8 {
                        write_planned_flag_bits(&mut flags, flag_bits, flag);
                        payloads.push(EncodedToken::LongLz(long_lz));
                        flag_bits += flag.len();
                        pos += long_lz.length as usize;
                        plan_long_lz_effect(&mut plan_nhfb, &mut plan_nlzb);
                        continue;
                    }
                }

                let flag = huff_flag_bits(plan_nlzb <= plan_nhfb);
                if flag_bits + flag.len() > 8 {
                    break;
                }
                write_planned_flag_bits(&mut flags, flag_bits, flag);
                payloads.push(EncodedToken::Literal(input[pos]));
                flag_bits += flag.len();
                pos += 1;
                plan_huff_effect(&mut plan_nhfb, &mut plan_nlzb);
            }

            self.emit_flags_byte(flags)?;
            self.emit_payloads(payloads, pos < input.len())?;
        }
        Ok(std::mem::take(&mut self.bits).finish())
    }

    fn emit_payloads(&mut self, payloads: Vec<EncodedToken>, more_input: bool) -> Result<()> {
        let mut consumed_flag_bits = 0usize;
        let mut decoder_enters_stmode = false;
        for payload in payloads {
            match payload {
                EncodedToken::Literal(byte) => {
                    consumed_flag_bits += huff_flag_bits(self.nlzb <= self.nhfb).len();
                    if consumed_flag_bits == 8 && self.num_huf >= 16 {
                        decoder_enters_stmode = true;
                    }
                    self.emit_literal(byte)?;
                }
                EncodedToken::ShortLz(short_lz) => {
                    consumed_flag_bits += 2;
                    self.emit_short_lz(short_lz)?;
                }
                EncodedToken::LongLz(long_lz) => {
                    consumed_flag_bits += long_lz_flag_bits(self.nlzb > self.nhfb).len();
                    self.emit_long_lz(long_lz)?;
                }
            }
        }

        if decoder_enters_stmode && more_input {
            self.emit_stmode_exit()?;
        }
        Ok(())
    }

    fn emit_flags_byte(&mut self, flags: u8) -> Result<()> {
        let flags_place = self
            .ch_set_c
            .iter()
            .position(|&value| (value >> 8) as u8 == flags)
            .ok_or(Error::InvalidHeader("RAR 1.3 flag byte is not encodable"))?;
        emit_decode_num(&mut self.bits, flags_place as u32, 5, DEC_HF2, POS_HF2)?;

        let mut cur_flags;
        let mut new_flags_place;
        loop {
            cur_flags = self.ch_set_c[flags_place] as u32;
            new_flags_place = self.n_to_pl_c[(cur_flags & 0xff) as usize] as usize;
            self.n_to_pl_c[(cur_flags & 0xff) as usize] =
                self.n_to_pl_c[(cur_flags & 0xff) as usize].wrapping_add(1);
            cur_flags += 1;
            if cur_flags & 0xff == 0 {
                corr_huff(&mut self.ch_set_c, &mut self.n_to_pl_c);
            } else {
                break;
            }
        }

        self.ch_set_c[flags_place] = self.ch_set_c[new_flags_place];
        self.ch_set_c[new_flags_place] = cur_flags as u16;
        Ok(())
    }

    fn emit_literal(&mut self, byte: u8) -> Result<()> {
        let byte_place = self
            .ch_set
            .iter()
            .position(|&value| (value >> 8) as u8 == byte)
            .ok_or(Error::InvalidHeader("RAR 1.3 literal is not encodable"))?;

        let (start_pos, dec_tab, pos_tab) = if self.avr_plc > 0x75ff {
            (8, DEC_HF4, POS_HF4)
        } else if self.avr_plc > 0x5dff {
            (6, DEC_HF3, POS_HF3)
        } else if self.avr_plc > 0x35ff {
            (5, DEC_HF2, POS_HF2)
        } else if self.avr_plc > 0x0dff {
            (5, DEC_HF1, POS_HF1)
        } else {
            (4, DEC_HF0, POS_HF0)
        };
        emit_decode_num(
            &mut self.bits,
            byte_place as u32,
            start_pos,
            dec_tab,
            pos_tab,
        )?;

        self.avr_plc += byte_place as u32;
        self.avr_plc -= self.avr_plc >> 8;
        self.nhfb += 16;
        if self.nhfb > 0xff {
            self.nhfb = 0x90;
            self.nlzb >>= 1;
        }
        self.num_huf += 1;

        let idx = byte_place;
        let mut cur_byte;
        let mut new_byte_place;
        loop {
            cur_byte = self.ch_set[idx] as u32;
            new_byte_place = self.n_to_pl[(cur_byte & 0xff) as usize] as usize;
            self.n_to_pl[(cur_byte & 0xff) as usize] =
                self.n_to_pl[(cur_byte & 0xff) as usize].wrapping_add(1);
            cur_byte += 1;
            if cur_byte & 0xff > 0xa1 {
                corr_huff(&mut self.ch_set, &mut self.n_to_pl);
            } else {
                break;
            }
        }

        self.ch_set[idx] = self.ch_set[new_byte_place];
        self.ch_set[new_byte_place] = cur_byte as u16;
        Ok(())
    }

    fn emit_short_lz(&mut self, short_lz: ShortLz) -> Result<()> {
        self.num_huf = 0;
        let length_place = short_lz.length - 2;
        let code_len = if self.avr_ln1 < 37 {
            self.short_len1(length_place as usize)
        } else {
            self.short_len2(length_place as usize)
        };
        let code_byte = if self.avr_ln1 < 37 {
            SHORT_XOR1[length_place as usize]
        } else {
            SHORT_XOR2[length_place as usize]
        };
        self.bits
            .write_bits((code_byte >> (8 - code_len)) as u32, code_len as usize);

        self.avr_ln1 += length_place;
        self.avr_ln1 -= self.avr_ln1 >> 4;

        let distance_value = short_lz.distance - 1;
        let distance_place = self
            .ch_set_a
            .iter()
            .position(|&value| value as u32 == distance_value)
            .ok_or(Error::InvalidHeader(
                "RAR 1.3 ShortLZ distance is not encodable",
            ))?;
        emit_decode_num(&mut self.bits, distance_place as u32, 5, DEC_HF2, POS_HF2)?;
        if distance_place > 0 {
            let last_distance = self.ch_set_a[distance_place - 1];
            self.ch_set_a[distance_place] = last_distance;
            self.ch_set_a[distance_place - 1] = distance_value as u16;
        }
        self.remember_match(short_lz.distance, short_lz.length);
        Ok(())
    }

    fn emit_long_lz(&mut self, long_lz: LongLz) -> Result<()> {
        self.num_huf = 0;
        self.nlzb += 16;
        if self.nlzb > 0xff {
            self.nlzb = 0x90;
            self.nhfb >>= 1;
        }
        let old_avr2 = self.avr_ln2;

        let length_code = long_lz.length - 3;
        emit_long_lz_length(&mut self.bits, length_code)?;
        self.avr_ln2 += length_code;
        self.avr_ln2 -= self.avr_ln2 >> 5;

        let distance_place = self.long_lz_distance_place(long_lz.distance)?;
        let (start_pos, dec_tab, pos_tab) = if self.avr_plc_b > 0x28ff {
            (5, DEC_HF2, POS_HF2)
        } else if self.avr_plc_b > 0x06ff {
            (5, DEC_HF1, POS_HF1)
        } else {
            (4, DEC_HF0, POS_HF0)
        };
        emit_decode_num(
            &mut self.bits,
            distance_place as u32,
            start_pos,
            dec_tab,
            pos_tab,
        )?;
        self.avr_plc_b += distance_place as u32;
        self.avr_plc_b -= self.avr_plc_b >> 8;

        let idx = distance_place;
        let mut distance;
        let mut new_distance_place;
        loop {
            distance = self.ch_set_b[idx] as u32;
            new_distance_place = self.n_to_pl_b[(distance & 0xff) as usize] as usize;
            self.n_to_pl_b[(distance & 0xff) as usize] =
                self.n_to_pl_b[(distance & 0xff) as usize].wrapping_add(1);
            distance += 1;
            if distance & 0xff == 0 {
                corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
            } else {
                break;
            }
        }

        self.ch_set_b[idx] = self.ch_set_b[new_distance_place];
        self.ch_set_b[new_distance_place] = distance as u16;

        let low_byte = ((long_lz.distance << 1) & 0xff) as u8;
        self.bits.write_bits((low_byte >> 1) as u32, 7);

        let old_avr3 = self.avr_ln3;
        if length_code != 1 && length_code != 4 {
            if length_code == 0 && long_lz.distance <= self.max_dist3 {
                self.avr_ln3 += 1;
                self.avr_ln3 -= self.avr_ln3 >> 8;
            } else if self.avr_ln3 > 0 {
                self.avr_ln3 -= 1;
            }
        }
        if old_avr3 > 0xb0 || (self.avr_plc >= 0x2a00 && old_avr2 < 0x40) {
            self.max_dist3 = 0x7f00;
        } else {
            self.max_dist3 = 0x2001;
        }

        self.remember_match(long_lz.distance, long_lz.length);
        Ok(())
    }

    fn long_lz_distance_place(&self, target_distance: u32) -> Result<usize> {
        let wanted_high = ((target_distance << 1) & 0xff00) as u16;
        self.ch_set_b
            .iter()
            .position(|&value| value & 0xff00 == wanted_high)
            .ok_or(Error::InvalidHeader(
                "RAR 1.3 LongLZ distance is not encodable",
            ))
    }

    fn emit_stmode_exit(&mut self) -> Result<()> {
        let (start_pos, dec_tab, pos_tab) = if self.avr_plc > 0x75ff {
            (8, DEC_HF4, POS_HF4)
        } else if self.avr_plc > 0x5dff {
            (6, DEC_HF3, POS_HF3)
        } else if self.avr_plc > 0x35ff {
            (5, DEC_HF2, POS_HF2)
        } else if self.avr_plc > 0x0dff {
            (5, DEC_HF1, POS_HF1)
        } else {
            (4, DEC_HF0, POS_HF0)
        };
        emit_decode_num(&mut self.bits, 0, start_pos, dec_tab, pos_tab)?;
        self.bits.write_bits(1, 1);
        self.num_huf = 0;
        Ok(())
    }

    fn init_huff(&mut self) {
        for i in 0..256 {
            self.ch_set[i] = (i as u16) << 8;
            self.ch_set_c[i] = ((0u8.wrapping_sub(i as u8) as u16) << 8) as u16;
            self.ch_set_b[i] = (i as u16) << 8;
        }
        self.n_to_pl = [0; 256];
        self.n_to_pl_b = [0; 256];
        self.n_to_pl_c = [0; 256];
        for i in 0..256 {
            self.ch_set_a[i] = i as u16;
        }
        corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
    }

    fn remember_match(&mut self, distance: u32, length: u32) {
        self.old_dist[self.old_dist_ptr] = distance;
        self.old_dist_ptr = (self.old_dist_ptr + 1) & 3;
        self.last_length = length;
        self.last_dist = distance;
    }

    fn short_len1(&self, pos: usize) -> u8 {
        if pos == 1 {
            3
        } else {
            SHORT_LEN1[pos]
        }
    }

    fn short_len2(&self, pos: usize) -> u8 {
        if pos == 3 {
            3
        } else {
            SHORT_LEN2[pos]
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodedToken {
    Literal(u8),
    ShortLz(ShortLz),
    LongLz(LongLz),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShortLz {
    distance: u32,
    length: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LongLz {
    distance: u32,
    length: u32,
}

fn huff_flag_bits(prefer_huff_on_one: bool) -> &'static [bool] {
    if prefer_huff_on_one {
        &[true]
    } else {
        &[false, true]
    }
}

fn long_lz_flag_bits(prefer_long_lz_on_one: bool) -> &'static [bool] {
    if prefer_long_lz_on_one {
        &[true]
    } else {
        &[false, true]
    }
}

fn write_planned_flag_bits(flags: &mut u8, start: usize, bits: &[bool]) {
    for (offset, &bit) in bits.iter().enumerate() {
        if bit {
            *flags |= 1 << (7 - start - offset);
        }
    }
}

fn plan_huff_effect(nhfb: &mut u32, nlzb: &mut u32) {
    *nhfb += 16;
    if *nhfb > 0xff {
        *nhfb = 0x90;
        *nlzb >>= 1;
    }
}

fn plan_long_lz_effect(nhfb: &mut u32, nlzb: &mut u32) {
    *nlzb += 16;
    if *nlzb > 0xff {
        *nlzb = 0x90;
        *nhfb >>= 1;
    }
}

fn find_short_lz(input: &[u8], pos: usize) -> Option<ShortLz> {
    if pos < 2 {
        return None;
    }

    let max_distance = pos.min(256);
    let mut best = ShortLz {
        distance: 0,
        length: 0,
    };
    for distance in 1..=max_distance {
        let mut length = 0usize;
        while length < 10
            && pos + length < input.len()
            && input[pos + length] == input[pos + length - distance]
        {
            length += 1;
        }
        if length >= 3 && length > best.length as usize {
            best = ShortLz {
                distance: distance as u32,
                length: length as u32,
            };
        }
    }

    (best.length >= 3).then_some(best)
}

fn find_long_lz(input: &[u8], pos: usize) -> Option<LongLz> {
    if pos < 257 {
        return None;
    }

    let max_distance = pos.min(0x8000);
    let mut best = LongLz {
        distance: 0,
        length: 0,
    };
    for distance in 257..=max_distance {
        let mut length = 0usize;
        while length < 18
            && pos + length < input.len()
            && input[pos + length] == input[pos + length - distance]
        {
            length += 1;
        }
        if length >= 3 && length > best.length as usize {
            best = LongLz {
                distance: distance as u32,
                length: length as u32,
            };
        }
    }

    (best.length >= 3).then_some(best)
}

fn emit_long_lz_length(bits: &mut BitWriter, length_code: u32) -> Result<()> {
    if length_code > 15 {
        return Err(Error::InvalidHeader(
            "RAR 1.3 LongLZ encoder length is not encodable",
        ));
    }
    bits.write_bits(1, length_code as usize + 1);
    Ok(())
}

fn emit_decode_num(
    bits: &mut BitWriter,
    target: u32,
    start_pos: u32,
    dec_tab: &[u16],
    pos_tab: &[u16],
) -> Result<()> {
    for len in start_pos as usize..=16 {
        for code in 0..(1u32 << len) {
            let bit_field = code << (16 - len);
            let (decoded, consumed) = simulate_decode_num(bit_field, start_pos, dec_tab, pos_tab);
            if decoded == target && consumed == len {
                bits.write_bits(code, len);
                return Ok(());
            }
        }
    }
    Err(Error::InvalidHeader(
        "RAR 1.3 DecodeNum value is not encodable",
    ))
}

fn simulate_decode_num(
    bit_field: u32,
    mut start_pos: u32,
    dec_tab: &[u16],
    pos_tab: &[u16],
) -> (u32, usize) {
    let num = bit_field & 0xfff0;
    let mut i = 0usize;
    while dec_tab[i] as u32 <= num {
        start_pos += 1;
        i += 1;
    }
    (
        ((num - if i > 0 { dec_tab[i - 1] as u32 } else { 0 }) >> (16 - start_pos))
            + pos_tab[start_pos as usize] as u32,
        start_pos as usize,
    )
}

struct Unpack15 {
    bits: BitReader,
    target: usize,
    output: Vec<u8>,
    window: [u8; 0x10000],
    unp_ptr: usize,
    prev_ptr: usize,
    first_win_done: bool,
    ch_set: [u16; 256],
    ch_set_a: [u16; 256],
    ch_set_b: [u16; 256],
    ch_set_c: [u16; 256],
    n_to_pl: [u8; 256],
    n_to_pl_b: [u8; 256],
    n_to_pl_c: [u8; 256],
    avr_plc: u32,
    avr_plc_b: u32,
    avr_ln1: u32,
    avr_ln2: u32,
    avr_ln3: u32,
    max_dist3: u32,
    nhfb: u32,
    nlzb: u32,
    num_huf: u32,
    buf60: u32,
    st_mode: bool,
    l_count: u32,
    flag_buf: u32,
    flags_cnt: i32,
    old_dist: [u32; 4],
    old_dist_ptr: usize,
    last_dist: u32,
    last_length: u32,
}

impl Unpack15 {
    fn new() -> Self {
        Self {
            bits: BitReader::new(&[]),
            target: 0,
            output: Vec::new(),
            window: [0; 0x10000],
            unp_ptr: 0,
            prev_ptr: 0,
            first_win_done: false,
            ch_set: [0; 256],
            ch_set_a: [0; 256],
            ch_set_b: [0; 256],
            ch_set_c: [0; 256],
            n_to_pl: [0; 256],
            n_to_pl_b: [0; 256],
            n_to_pl_c: [0; 256],
            avr_plc: 0x3500,
            avr_plc_b: 0,
            avr_ln1: 0,
            avr_ln2: 0,
            avr_ln3: 0,
            max_dist3: 0x2001,
            nhfb: 0x80,
            nlzb: 0x80,
            num_huf: 0,
            buf60: 0,
            st_mode: false,
            l_count: 0,
            flag_buf: 0,
            flags_cnt: 0,
            old_dist: [u32::MAX; 4],
            old_dist_ptr: 0,
            last_dist: u32::MAX,
            last_length: 0,
        }
    }

    fn decode_member(&mut self, input: &[u8], target: usize, solid: bool) -> Result<Vec<u8>> {
        self.bits = BitReader::new(input);
        self.target = target;
        self.output = Vec::with_capacity(target);
        self.flags_cnt = 0;
        self.flag_buf = 0;
        self.st_mode = false;
        self.l_count = 0;

        if !solid {
            self.reset_non_solid();
        }

        if self.target == 0 {
            return Ok(Vec::new());
        }

        self.get_flags_buf();
        self.flags_cnt = 8;

        while self.output.len() < self.target {
            self.unp_ptr &= 0xffff;
            self.first_win_done |= self.prev_ptr > self.unp_ptr;
            self.prev_ptr = self.unp_ptr;

            if self.st_mode {
                self.huff_decode()?;
                continue;
            }

            self.flags_cnt -= 1;
            if self.flags_cnt < 0 {
                self.get_flags_buf();
                self.flags_cnt = 7;
            }

            if self.flag_buf & 0x80 != 0 {
                self.flag_buf = (self.flag_buf << 1) & 0xff;
                if self.nlzb > self.nhfb {
                    self.long_lz()?;
                } else {
                    self.huff_decode()?;
                }
            } else {
                self.flag_buf = (self.flag_buf << 1) & 0xff;
                self.flags_cnt -= 1;
                if self.flags_cnt < 0 {
                    self.get_flags_buf();
                    self.flags_cnt = 7;
                }
                if self.flag_buf & 0x80 != 0 {
                    self.flag_buf = (self.flag_buf << 1) & 0xff;
                    if self.nlzb > self.nhfb {
                        self.huff_decode()?;
                    } else {
                        self.long_lz()?;
                    }
                } else {
                    self.flag_buf = (self.flag_buf << 1) & 0xff;
                    self.short_lz()?;
                }
            }
        }

        Ok(std::mem::take(&mut self.output))
    }

    fn reset_non_solid(&mut self) {
        self.window = [0; 0x10000];
        self.unp_ptr = 0;
        self.prev_ptr = 0;
        self.first_win_done = false;
        self.avr_plc_b = 0;
        self.avr_ln1 = 0;
        self.avr_ln2 = 0;
        self.avr_ln3 = 0;
        self.num_huf = 0;
        self.buf60 = 0;
        self.avr_plc = 0x3500;
        self.max_dist3 = 0x2001;
        self.nhfb = 0x80;
        self.nlzb = 0x80;
        self.old_dist = [u32::MAX; 4];
        self.old_dist_ptr = 0;
        self.last_dist = u32::MAX;
        self.last_length = 0;
        self.init_huff();
    }

    fn short_lz(&mut self) -> Result<()> {
        self.num_huf = 0;
        let mut bit_field = self.bits.get_bits();
        if self.l_count == 2 {
            self.bits.add_bits(1);
            if bit_field >= 0x8000 {
                self.copy_string(self.last_dist, self.last_length)?;
                return Ok(());
            }
            bit_field = (bit_field << 1) & 0xffff;
            self.l_count = 0;
        }

        let bit_byte = (bit_field >> 8) as u8;
        let mut length = 0usize;
        if self.avr_ln1 < 37 {
            while length < SHORT_XOR1.len() {
                let short_len = self.short_len1(length);
                let mask = (!(0xffu16 >> short_len)) as u8;
                if ((bit_byte ^ SHORT_XOR1[length]) & mask) == 0 {
                    break;
                }
                length += 1;
            }
            self.bits.add_bits(self.short_len1(length) as usize);
        } else {
            while length < SHORT_XOR2.len() {
                let short_len = self.short_len2(length);
                let mask = (!(0xffu16 >> short_len)) as u8;
                if ((bit_byte ^ SHORT_XOR2[length]) & mask) == 0 {
                    break;
                }
                length += 1;
            }
            self.bits.add_bits(self.short_len2(length) as usize);
        }

        let mut length = length as u32;
        if length >= 9 {
            if length == 9 {
                self.l_count += 1;
                self.copy_string(self.last_dist, self.last_length)?;
                return Ok(());
            }
            if length == 14 {
                self.l_count = 0;
                length = self.decode_num(self.bits.get_bits(), 3, DEC_L2, POS_L2) + 5;
                let distance = (self.bits.get_bits() >> 1) | 0x8000;
                self.bits.add_bits(15);
                self.last_length = length;
                self.last_dist = distance;
                self.copy_string(distance, length)?;
                return Ok(());
            }

            self.l_count = 0;
            let save_length = length;
            let distance =
                self.old_dist[(self.old_dist_ptr.wrapping_sub((length - 9) as usize)) & 3];
            length = self.decode_num(self.bits.get_bits(), 2, DEC_L1, POS_L1) + 2;
            if length == 0x101 && save_length == 10 {
                self.buf60 ^= 1;
                return Ok(());
            }
            if distance > 256 {
                length += 1;
            }
            if distance >= self.max_dist3 {
                length += 1;
            }

            self.remember_match(distance, length);
            self.copy_string(distance, length)?;
            return Ok(());
        }

        self.l_count = 0;
        self.avr_ln1 += length;
        self.avr_ln1 -= self.avr_ln1 >> 4;

        let distance_place =
            (self.decode_num(self.bits.get_bits(), 5, DEC_HF2, POS_HF2) & 0xff) as usize;
        let mut distance = self.ch_set_a[distance_place] as u32;
        if distance_place > 0 {
            let last_distance = self.ch_set_a[distance_place - 1];
            self.ch_set_a[distance_place] = last_distance;
            self.ch_set_a[distance_place - 1] = distance as u16;
        }
        length += 2;
        distance += 1;
        self.remember_match(distance, length);
        self.copy_string(distance, length)
    }

    fn long_lz(&mut self) -> Result<()> {
        self.num_huf = 0;
        self.nlzb += 16;
        if self.nlzb > 0xff {
            self.nlzb = 0x90;
            self.nhfb >>= 1;
        }
        let old_avr2 = self.avr_ln2;

        let bit_field = self.bits.get_bits();
        let mut length = if self.avr_ln2 >= 122 {
            self.decode_num(bit_field, 3, DEC_L2, POS_L2)
        } else if self.avr_ln2 >= 64 {
            self.decode_num(bit_field, 2, DEC_L1, POS_L1)
        } else if bit_field < 0x100 {
            self.bits.add_bits(16);
            bit_field
        } else {
            let mut length = 0u32;
            while ((bit_field << length) & 0x8000) == 0 {
                length += 1;
            }
            self.bits.add_bits((length + 1) as usize);
            length
        };

        self.avr_ln2 += length;
        self.avr_ln2 -= self.avr_ln2 >> 5;

        let bit_field = self.bits.get_bits();
        let distance_place = if self.avr_plc_b > 0x28ff {
            self.decode_num(bit_field, 5, DEC_HF2, POS_HF2)
        } else if self.avr_plc_b > 0x06ff {
            self.decode_num(bit_field, 5, DEC_HF1, POS_HF1)
        } else {
            self.decode_num(bit_field, 4, DEC_HF0, POS_HF0)
        };

        self.avr_plc_b += distance_place;
        self.avr_plc_b -= self.avr_plc_b >> 8;

        let idx = (distance_place & 0xff) as usize;
        let mut distance;
        let mut new_distance_place;
        loop {
            distance = self.ch_set_b[idx] as u32;
            new_distance_place = self.n_to_pl_b[(distance & 0xff) as usize] as usize;
            self.n_to_pl_b[(distance & 0xff) as usize] =
                self.n_to_pl_b[(distance & 0xff) as usize].wrapping_add(1);
            distance += 1;
            if distance & 0xff == 0 {
                corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
            } else {
                break;
            }
        }

        self.ch_set_b[idx] = self.ch_set_b[new_distance_place];
        self.ch_set_b[new_distance_place] = distance as u16;

        distance = ((distance & 0xff00) | (self.bits.get_bits() >> 8)) >> 1;
        self.bits.add_bits(7);

        let old_avr3 = self.avr_ln3;
        if length != 1 && length != 4 {
            if length == 0 && distance <= self.max_dist3 {
                self.avr_ln3 += 1;
                self.avr_ln3 -= self.avr_ln3 >> 8;
            } else if self.avr_ln3 > 0 {
                self.avr_ln3 -= 1;
            }
        }
        length += 3;
        if distance >= self.max_dist3 {
            length += 1;
        }
        if distance <= 256 {
            length += 8;
        }
        if old_avr3 > 0xb0 || (self.avr_plc >= 0x2a00 && old_avr2 < 0x40) {
            self.max_dist3 = 0x7f00;
        } else {
            self.max_dist3 = 0x2001;
        }

        self.remember_match(distance, length);
        self.copy_string(distance, length)
    }

    fn huff_decode(&mut self) -> Result<()> {
        let bit_field = self.bits.get_bits();

        let mut byte_place = if self.avr_plc > 0x75ff {
            self.decode_num(bit_field, 8, DEC_HF4, POS_HF4)
        } else if self.avr_plc > 0x5dff {
            self.decode_num(bit_field, 6, DEC_HF3, POS_HF3)
        } else if self.avr_plc > 0x35ff {
            self.decode_num(bit_field, 5, DEC_HF2, POS_HF2)
        } else if self.avr_plc > 0x0dff {
            self.decode_num(bit_field, 5, DEC_HF1, POS_HF1)
        } else {
            self.decode_num(bit_field, 4, DEC_HF0, POS_HF0)
        } & 0xff;

        if self.st_mode {
            if byte_place == 0 && bit_field > 0x0fff {
                byte_place = 0x100;
            }
            if byte_place == 0 {
                let bit_field = self.bits.get_bits();
                self.bits.add_bits(1);
                if bit_field & 0x8000 != 0 {
                    self.num_huf = 0;
                    self.st_mode = false;
                    return Ok(());
                }

                let length = if bit_field & 0x4000 != 0 { 4 } else { 3 };
                self.bits.add_bits(1);
                let mut distance = self.decode_num(self.bits.get_bits(), 5, DEC_HF2, POS_HF2);
                distance = (distance << 5) | (self.bits.get_bits() >> 11);
                self.bits.add_bits(5);
                self.copy_string(distance, length)?;
                return Ok(());
            }
            byte_place -= 1;
        } else {
            if self.num_huf >= 16 && self.flags_cnt == 0 {
                self.st_mode = true;
            }
            self.num_huf += 1;
        }

        self.avr_plc += byte_place;
        self.avr_plc -= self.avr_plc >> 8;
        self.nhfb += 16;
        if self.nhfb > 0xff {
            self.nhfb = 0x90;
            self.nlzb >>= 1;
        }

        let byte = (self.ch_set[byte_place as usize] >> 8) as u8;
        self.put_byte(byte)?;

        let idx = byte_place as usize;
        let mut cur_byte;
        let mut new_byte_place;
        loop {
            cur_byte = self.ch_set[idx] as u32;
            new_byte_place = self.n_to_pl[(cur_byte & 0xff) as usize] as usize;
            self.n_to_pl[(cur_byte & 0xff) as usize] =
                self.n_to_pl[(cur_byte & 0xff) as usize].wrapping_add(1);
            cur_byte += 1;
            if cur_byte & 0xff > 0xa1 {
                corr_huff(&mut self.ch_set, &mut self.n_to_pl);
            } else {
                break;
            }
        }

        self.ch_set[idx] = self.ch_set[new_byte_place];
        self.ch_set[new_byte_place] = cur_byte as u16;
        Ok(())
    }

    fn get_flags_buf(&mut self) {
        let flags_place = self.decode_num(self.bits.get_bits(), 5, DEC_HF2, POS_HF2) as usize;
        if flags_place >= self.ch_set_c.len() {
            return;
        }

        let mut flags;
        let mut new_flags_place;
        loop {
            flags = self.ch_set_c[flags_place] as u32;
            new_flags_place = self.n_to_pl_c[(flags & 0xff) as usize] as usize;
            self.n_to_pl_c[(flags & 0xff) as usize] =
                self.n_to_pl_c[(flags & 0xff) as usize].wrapping_add(1);
            self.flag_buf = flags >> 8;
            flags += 1;
            if flags & 0xff == 0 {
                corr_huff(&mut self.ch_set_c, &mut self.n_to_pl_c);
            } else {
                break;
            }
        }

        self.ch_set_c[flags_place] = self.ch_set_c[new_flags_place];
        self.ch_set_c[new_flags_place] = flags as u16;
    }

    fn decode_num(
        &mut self,
        num: u32,
        mut start_pos: u32,
        dec_tab: &[u16],
        pos_tab: &[u16],
    ) -> u32 {
        let num = num & 0xfff0;
        let mut i = 0usize;
        while dec_tab[i] as u32 <= num {
            start_pos += 1;
            i += 1;
        }
        self.bits.add_bits(start_pos as usize);
        ((num - if i > 0 { dec_tab[i - 1] as u32 } else { 0 }) >> (16 - start_pos))
            + pos_tab[start_pos as usize] as u32
    }

    fn copy_string(&mut self, distance: u32, length: u32) -> Result<()> {
        if self.output.len() + length as usize > self.target {
            return Err(Error::InvalidHeader("RAR 1.3 match exceeds output size"));
        }

        if (!self.first_win_done && distance as usize > self.unp_ptr)
            || distance as usize > 0x10000
            || distance == 0
        {
            for _ in 0..length {
                self.put_byte(0)?;
            }
        } else {
            for _ in 0..length {
                let byte = self.window[(self.unp_ptr.wrapping_sub(distance as usize)) & 0xffff];
                self.put_byte(byte)?;
            }
        }
        Ok(())
    }

    fn put_byte(&mut self, byte: u8) -> Result<()> {
        if self.output.len() >= self.target {
            return Err(Error::InvalidHeader("RAR 1.3 literal exceeds output size"));
        }
        self.window[self.unp_ptr] = byte;
        self.unp_ptr = (self.unp_ptr + 1) & 0xffff;
        self.output.push(byte);
        Ok(())
    }

    fn remember_match(&mut self, distance: u32, length: u32) {
        self.old_dist[self.old_dist_ptr] = distance;
        self.old_dist_ptr = (self.old_dist_ptr + 1) & 3;
        self.last_length = length;
        self.last_dist = distance;
    }

    fn short_len1(&self, pos: usize) -> u32 {
        if pos == 1 {
            self.buf60 + 3
        } else {
            SHORT_LEN1[pos] as u32
        }
    }

    fn short_len2(&self, pos: usize) -> u32 {
        if pos == 3 {
            self.buf60 + 3
        } else {
            SHORT_LEN2[pos] as u32
        }
    }

    fn init_huff(&mut self) {
        for i in 0..256 {
            self.ch_set[i] = (i as u16) << 8;
            self.ch_set_b[i] = (i as u16) << 8;
            self.ch_set_a[i] = i as u16;
            self.ch_set_c[i] = ((0u8.wrapping_sub(i as u8) as u16) << 8) as u16;
        }
        self.n_to_pl = [0; 256];
        self.n_to_pl_b = [0; 256];
        self.n_to_pl_c = [0; 256];
        corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
    }
}

fn corr_huff(char_set: &mut [u16; 256], num_to_place: &mut [u8; 256]) {
    let mut pos = 0usize;
    for rank in (0..=7).rev() {
        for _ in 0..32 {
            char_set[pos] = (char_set[pos] & !0xff) | rank;
            pos += 1;
        }
    }
    *num_to_place = [0; 256];
    for rank in (0..=6).rev() {
        num_to_place[rank] = ((7 - rank) * 32) as u8;
    }
}

struct BitReader {
    input: Vec<u8>,
    bit_pos: usize,
}

impl BitReader {
    fn new(input: &[u8]) -> Self {
        Self {
            input: input.to_vec(),
            bit_pos: 0,
        }
    }

    fn get_bits(&self) -> u32 {
        let mut value = 0u32;
        for i in 0..16 {
            value <<= 1;
            let bit_index = self.bit_pos + i;
            let byte = self.input.get(bit_index / 8).copied().unwrap_or(0);
            value |= ((byte >> (7 - (bit_index % 8))) & 1) as u32;
        }
        value
    }

    fn add_bits(&mut self, count: usize) {
        self.bit_pos += count;
    }
}

#[derive(Default)]
struct BitWriter {
    output: Vec<u8>,
    bit_pos: usize,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            output: Vec::new(),
            bit_pos: 0,
        }
    }

    fn write_bits(&mut self, value: u32, count: usize) {
        for i in (0..count).rev() {
            let bit = ((value >> i) & 1) as u8;
            if self.bit_pos % 8 == 0 {
                self.output.push(0);
            }
            if bit != 0 {
                let idx = self.output.len() - 1;
                self.output[idx] |= 1 << (7 - (self.bit_pos % 8));
            }
            self.bit_pos += 1;
        }
    }

    fn finish(self) -> Vec<u8> {
        self.output
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rar13Cipher {
    key: [u8; 3],
}

impl Rar13Cipher {
    fn new(password: &[u8]) -> Self {
        let mut key = [0u8; 3];
        for &byte in password {
            key[0] = key[0].wrapping_add(byte);
            key[1] ^= byte;
            key[2] = key[2].wrapping_add(byte).rotate_left(1);
        }
        Self { key }
    }

    fn new_comment() -> Self {
        Self { key: [0, 7, 77] }
    }

    fn encrypt_in_place(mut self, data: &mut [u8]) {
        for byte in data {
            self.advance();
            *byte = byte.wrapping_add(self.key[0]);
        }
    }

    fn decrypt_in_place(mut self, data: &mut [u8]) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_reads_stored_archive() {
        let input = [
            StoredEntry {
                name: b"README.md",
                data: b"hello rar 1.3",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
            StoredEntry {
                name: b"docs",
                data: b"",
                file_time: 0,
                file_attr: 0x10,
                password: None,
                file_comment: None,
            },
        ];

        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.main.flags, 0x80);
        assert_eq!(archive.entries.len(), 2);
        assert_eq!(archive.entries[0].name_lossy(), "README.md");
        assert_eq!(
            archive.entries[0].stored_data(None).unwrap(),
            b"hello rar 1.3"
        );
        assert!(archive.entries[1].is_directory());

        let extracted = archive.extract_stored(None).unwrap();
        assert_eq!(extracted[0].data, b"hello rar 1.3");
        assert!(extracted[1].is_directory);
    }

    #[test]
    fn rejects_malformed_main_header_boundaries() {
        assert_eq!(MainHeader::parse(b"RE~"), Err(Error::TooShort));

        let mut too_small = Vec::from(&b"RE~^"[..]);
        too_small.extend_from_slice(&6u16.to_le_bytes());
        too_small.push(0x80);
        assert_eq!(
            MainHeader::parse(&too_small),
            Err(Error::InvalidHeader(
                "RAR 1.3 main header is shorter than 7 bytes"
            ))
        );

        let mut truncated_extra = Vec::from(&b"RE~^"[..]);
        truncated_extra.extend_from_slice(&8u16.to_le_bytes());
        truncated_extra.push(0x80);
        assert_eq!(MainHeader::parse(&truncated_extra), Err(Error::TooShort));

        assert_eq!(
            Archive::parse(b"Rar!\x1a\x07\x00"),
            Err(Error::UnsupportedSignature)
        );
    }

    #[test]
    fn rejects_file_header_shorter_than_its_name() {
        let mut bytes = Vec::from(&b"RE~^"[..]);
        bytes.extend_from_slice(&7u16.to_le_bytes());
        bytes.push(0x80);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&(FILE_HEAD_BASE_SIZE as u16).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.push(0x20);
        bytes.push(0);
        bytes.push(DEFAULT_UNP_VER);
        bytes.push(10);
        bytes.push(METHOD_STORE);

        assert_eq!(
            Archive::parse(&bytes),
            Err(Error::InvalidHeader(
                "RAR 1.3 file header is shorter than its name"
            ))
        );
    }

    #[test]
    fn rejects_truncated_file_payload_during_parse() {
        let input = [StoredEntry {
            name: b"hello.txt",
            data: b"hello",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];
        let mut bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        bytes.pop();

        assert_eq!(Archive::parse(&bytes), Err(Error::TooShort));
    }

    #[test]
    fn returns_none_for_absent_archive_comment() {
        let bytes = write_stored_archive(&[], WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();

        assert_eq!(archive.archive_comment().unwrap(), None);
    }

    #[test]
    fn rejects_normal_extract_on_split_entries() {
        let entry = StoredEntry {
            name: b"split.bin",
            data: b"abcdefghijklmnopqrstuvwxyz",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };
        let volumes = write_stored_volumes(entry, WriterOptions::default(), 8).unwrap();
        let first = Archive::parse(&volumes[0]).unwrap();

        assert_eq!(
            first.extract(None),
            Err(Error::InvalidHeader(
                "RAR 1.3 split entry requires multivolume extraction"
            ))
        );
        assert_eq!(
            first.extract_stored(None),
            Err(Error::InvalidHeader(
                "RAR 1.3 split entry requires multivolume extraction"
            ))
        );
    }

    #[test]
    fn rejects_malformed_comment_extensions() {
        let packed_too_short = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_COMMENT | MHD_PACK_COMMENT,
                head_size: MAIN_HEAD_SIZE,
                extra: 1u16.to_le_bytes().to_vec(),
            },
            entries: Vec::new(),
        };
        assert_eq!(
            packed_too_short.archive_comment(),
            Err(Error::InvalidHeader(
                "RAR 1.3 packed archive comment is shorter than size field"
            ))
        );

        let unpacked_too_short = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_COMMENT,
                head_size: MAIN_HEAD_SIZE,
                extra: 4u16.to_le_bytes().to_vec(),
            },
            entries: Vec::new(),
        };
        assert_eq!(unpacked_too_short.archive_comment(), Err(Error::TooShort));
    }

    #[test]
    fn rejects_malformed_av_extensions() {
        let too_short = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_AV,
                head_size: MAIN_HEAD_SIZE,
                extra: 5u16.to_le_bytes().to_vec(),
            },
            entries: Vec::new(),
        };
        assert_eq!(
            too_short.authenticity_verification(),
            Err(Error::InvalidHeader("RAR 1.3 AV payload is too short"))
        );

        let bad_prefix = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_AV,
                head_size: MAIN_HEAD_SIZE,
                extra: {
                    let mut extra = 6u16.to_le_bytes().to_vec();
                    extra.extend_from_slice(b"badbad");
                    extra
                },
            },
            entries: Vec::new(),
        };
        assert_eq!(
            bad_prefix.authenticity_verification(),
            Err(Error::InvalidHeader("RAR 1.3 AV prefix mismatch"))
        );
    }

    #[test]
    fn writes_and_reads_encrypted_stored_archive() {
        let input = [StoredEntry {
            name: b"secret.txt",
            data: b"secret bytes",
            file_time: 0,
            file_attr: 0x20,
            password: Some(b"pass"),
            file_comment: None,
        }];

        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.entries[0].is_encrypted());
        assert!(matches!(
            archive.entries[0].stored_data(None),
            Err(Error::NeedPassword)
        ));
        assert_eq!(
            archive.entries[0].stored_data(Some(b"pass")).unwrap(),
            b"secret bytes"
        );

        let extracted = archive.extract_stored(Some(b"pass")).unwrap();
        assert_eq!(extracted[0].data, b"secret bytes");
    }

    #[test]
    fn writes_and_reads_archive_comment() {
        let input = [StoredEntry {
            name: b"README.md",
            data: b"hello rar 1.3",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_stored_archive_with_comment(
            &input,
            WriterOptions::default(),
            Some(b"This is an archive comment."),
        )
        .unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.main.has_archive_comment());
        assert!(archive.main.has_packed_comment());
        assert_eq!(
            archive.archive_comment().unwrap().as_deref(),
            Some(&b"This is an archive comment."[..])
        );
        assert_eq!(archive.extract(None).unwrap()[0].data, b"hello rar 1.3");
    }

    #[test]
    fn writes_and_reads_file_comment() {
        let input = [StoredEntry {
            name: b"README.md",
            data: b"hello rar 1.3",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: Some(b"file comment\r\n"),
        }];

        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.entries[0].has_file_comment());
        assert_eq!(
            archive.entries[0].file_comment().unwrap().as_deref(),
            Some(&b"file comment\r\n"[..])
        );
        assert_eq!(archive.extract(None).unwrap()[0].data, b"hello rar 1.3");
    }

    #[test]
    fn writes_and_reads_literal_only_compressed_archive() {
        let input = [FileEntry {
            name: b"tiny.txt",
            data: b"literal bytes over sixteen",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.main.flags, 0x80);
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].name, b"tiny.txt");
        assert!(!archive.entries[0].is_stored());
        assert_eq!(archive.entries[0].header.method, 3);
        assert!(archive.entries[0].header.pack_size > 0);

        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, b"literal bytes over sixteen");
    }

    #[test]
    fn writes_and_reads_literal_only_compressed_archive_with_repeated_stmode() {
        let data =
            b"this literal-only payload is long enough to enter and exit stmode more than once";
        let input = [FileEntry {
            name: b"long.txt",
            data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.entries[0].header.method, 3);

        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn compressed_writer_emits_short_lz_matches() {
        let data = b"abcabcabcabcabcabcabcabcabcabcabcabc";
        let input = [FileEntry {
            name: b"repeat.txt",
            data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.entries[0].header.method, 3);
        assert!(
            archive.entries[0].header.pack_size < data.len() as u32,
            "ShortLZ should make the repeated payload smaller than stored data"
        );

        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn compressed_writer_emits_long_lz_matches() {
        let mut data = short_lz_resistant_prefix(300);
        data.extend_from_slice(&data[..32].to_vec());
        assert_eq!(
            find_long_lz(&data, 300),
            Some(LongLz {
                distance: 300,
                length: 18
            })
        );
        let input = [FileEntry {
            name: b"far.txt",
            data: &data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let literal_only = Unpack15Encoder::new()
            .encode_literals_only(&data)
            .unwrap()
            .len();
        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.entries[0].header.method, 3);
        assert!(
            (archive.entries[0].header.pack_size as usize) < literal_only,
            "LongLZ should make a >256-byte-distance repeat smaller than literal-only output"
        );

        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn writes_and_reads_solid_compressed_archive() {
        let input = [
            FileEntry {
                name: b"first.txt",
                data: b"first member primes the adaptive unpack15 state",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
            FileEntry {
                name: b"second.txt",
                data: b"second member is encoded without resetting that state",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
        ];
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let options = WriterOptions {
            target: ArchiveVersion::Rar14,
            features,
        };

        let bytes = write_compressed_archive(&input, options).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.main.is_solid());
        assert_eq!(archive.entries.len(), 2);
        assert!(archive
            .entries
            .iter()
            .all(|entry| entry.header.flags & LHD_SOLID != 0));

        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, input[0].data);
        assert_eq!(extracted[1].data, input[1].data);
    }

    #[test]
    fn writes_and_reads_encrypted_compressed_archive() {
        let input = [FileEntry {
            name: b"secret.txt",
            data: b"secret compressed bytes over sixteen",
            file_time: 0,
            file_attr: 0x20,
            password: Some(b"pass"),
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.entries[0].is_encrypted());
        assert_eq!(archive.entries[0].header.method, 3);
        assert!(matches!(archive.extract(None), Err(Error::NeedPassword)));

        let extracted = archive.extract(Some(b"pass")).unwrap();
        assert_eq!(extracted[0].data, input[0].data);
    }

    #[test]
    fn writes_and_reads_compressed_file_comment() {
        let input = [FileEntry {
            name: b"commented.txt",
            data: b"compressed member with file comment",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: Some(b"compressed file comment"),
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(
            archive.entries[0].file_comment().unwrap().as_deref(),
            Some(&b"compressed file comment"[..])
        );

        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, input[0].data);
    }

    #[test]
    fn writes_and_reads_stored_multivolume_archive() {
        let entry = StoredEntry {
            name: b"random.bin",
            data: b"abcdefghijklmnopqrstuvwxyz0123456789",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };

        let bytes = write_stored_volumes(entry, WriterOptions::default(), 10).unwrap();
        assert_eq!(bytes.len(), 4);
        let volumes: Vec<_> = bytes
            .iter()
            .map(|bytes| Archive::parse(bytes).unwrap())
            .collect();
        assert!(volumes.iter().all(|archive| archive.main.is_volume()));
        assert!(!volumes[0].entries[0].is_split_before());
        assert!(volumes[0].entries[0].is_split_after());
        assert!(volumes[1].entries[0].is_split_before());
        assert!(volumes[1].entries[0].is_split_after());
        assert!(volumes[3].entries[0].is_split_before());
        assert!(!volumes[3].entries[0].is_split_after());
        assert!(volumes.iter().all(|archive| archive.entries[0].is_stored()));

        let extracted = extract_volumes(&volumes, None).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].name, b"random.bin");
        assert_eq!(extracted[0].data, entry.data);
    }

    #[test]
    fn writes_and_reads_compressed_multivolume_archive() {
        let data = b"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc";
        let entry = FileEntry {
            name: b"repeat.txt",
            data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };

        let bytes = write_compressed_volumes(entry, WriterOptions::default(), 8).unwrap();
        assert!(bytes.len() >= 2);
        let volumes: Vec<_> = bytes
            .iter()
            .map(|bytes| Archive::parse(bytes).unwrap())
            .collect();
        assert!(volumes.iter().all(|archive| archive.main.is_volume()));
        assert!(!volumes[0].entries[0].is_stored());
        assert!(volumes[0].entries[0].is_split_after());
        assert!(volumes.last().unwrap().entries[0].is_split_before());
        assert!(!volumes.last().unwrap().entries[0].is_split_after());

        let extracted = extract_volumes(&volumes, None).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].name, b"repeat.txt");
        assert_eq!(extracted[0].data, data);
    }

    fn short_lz_resistant_prefix(len: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(len);
        while data.len() < len {
            let next = (0u8..=u8::MAX)
                .find(|&candidate| {
                    if data.len() < 2 {
                        return true;
                    }
                    let start = data.len().saturating_sub(256);
                    !data[start..].windows(3).any(|window| {
                        window == [data[data.len() - 2], data[data.len() - 1], candidate]
                    })
                })
                .expect("byte alphabet can avoid local 3-byte repeats");
            data.push(next);
        }
        data
    }

    #[test]
    fn writes_empty_compressed_archive_member() {
        let input = [FileEntry {
            name: b"empty.bin",
            data: b"",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.entries[0].header.method, 3);
        assert_eq!(archive.entries[0].header.pack_size, 0);

        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, b"");
    }

    #[test]
    fn rejects_rar5_only_features_for_rar13() {
        let mut features = FeatureSet::store_only();
        features.quick_open = true;

        let options = WriterOptions {
            target: ArchiveVersion::Rar13,
            features,
        };
        let err = write_stored_archive(&[], options).unwrap_err();
        assert_eq!(
            err,
            Error::UnsupportedFeature {
                version: ArchiveVersion::Rar13,
                feature: "quick_open"
            }
        );
    }

    #[test]
    fn rejects_unimplemented_rar13_writer_features() {
        let mut features = FeatureSet::store_only();
        features.sfx = true;

        let options = WriterOptions {
            target: ArchiveVersion::Rar14,
            features,
        };
        let err = write_stored_archive(&[], options).unwrap_err();
        assert_eq!(
            err,
            Error::UnsupportedFeature {
                version: ArchiveVersion::Rar14,
                feature: "sfx"
            }
        );
    }

    #[test]
    fn file_checksum_matches_rar13_algorithm() {
        assert_eq!(file_checksum(b""), 0x0000);
        assert_eq!(file_checksum(b"123456789"), 0xc78a);
    }
}
