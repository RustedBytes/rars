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
const MHD_ALWAYS_SET: u8 = 0x80;
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
    if !options.target.is_rar13_family() {
        return Err(Error::UnsupportedVersion(options.target));
    }
    options.features.validate_for(options.target)?;
    validate_stored_writer_features(options.target, options.features)?;

    let mut out = Vec::new();
    write_main_header(&mut out, options.features);

    for entry in entries {
        validate_stored_entry(entry)?;
        write_stored_entry(&mut out, entry, options.features)?;
    }

    Ok(out)
}

fn validate_stored_writer_features(version: ArchiveVersion, features: FeatureSet) -> Result<()> {
    reject_writer_feature(version, features.archive_comment, "archive_comment")?;
    reject_writer_feature(version, features.file_comment, "file_comment")?;
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

fn write_main_header(out: &mut Vec<u8>, features: FeatureSet) {
    let mut flags = MHD_ALWAYS_SET;
    if features.archive_comment {
        flags |= MHD_COMMENT;
    }
    if features.solid {
        flags |= MHD_SOLID;
    }
    out.extend_from_slice(RAR13_SIGNATURE);
    out.extend_from_slice(&MAIN_HEAD_SIZE.to_le_bytes());
    out.push(flags);
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
    if features.file_comment {
        flags |= LHD_COMMENT;
    }
    if features.solid {
        flags |= LHD_SOLID;
    }

    let head_size = FILE_HEAD_BASE_SIZE + entry.name.len();
    let mut body = entry.data.to_vec();
    if let Some(password) = entry.password {
        Rar13Cipher::new(password).encrypt_in_place(&mut body);
    }

    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&(entry.data.len() as u32).to_le_bytes());
    out.extend_from_slice(&file_checksum(entry.data).to_le_bytes());
    out.extend_from_slice(&(head_size as u16).to_le_bytes());
    out.extend_from_slice(&entry.file_time.to_le_bytes());
    out.push(entry.file_attr);
    out.push(flags);
    out.push(DEFAULT_UNP_VER);
    out.push(entry.name.len() as u8);
    out.push(METHOD_STORE);
    out.extend_from_slice(entry.name);
    out.extend_from_slice(&body);
    Ok(())
}

fn validate_stored_entry(entry: &StoredEntry<'_>) -> Result<()> {
    if entry.name.is_empty() {
        return Err(Error::InvalidHeader("RAR 1.3 file name is empty"));
    }
    if entry.name.len() > u8::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 file name is longer than 255 bytes",
        ));
    }
    if entry.data.len() > u32::MAX as usize {
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

fn unpack15_decode(input: &[u8], output_size: usize) -> Result<Vec<u8>> {
    let mut decoder = Unpack15::new();
    decoder.decode_member(input, output_size, false)
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
            },
            StoredEntry {
                name: b"docs",
                data: b"",
                file_time: 0,
                file_attr: 0x10,
                password: None,
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
    fn writes_and_reads_encrypted_stored_archive() {
        let input = [StoredEntry {
            name: b"secret.txt",
            data: b"secret bytes",
            file_time: 0,
            file_attr: 0x20,
            password: Some(b"pass"),
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
        features.archive_comment = true;

        let options = WriterOptions {
            target: ArchiveVersion::Rar14,
            features,
        };
        let err = write_stored_archive(&[], options).unwrap_err();
        assert_eq!(
            err,
            Error::UnsupportedFeature {
                version: ArchiveVersion::Rar14,
                feature: "archive_comment"
            }
        );
    }

    #[test]
    fn file_checksum_matches_rar13_algorithm() {
        assert_eq!(file_checksum(b""), 0x0000);
        assert_eq!(file_checksum(b"123456789"), 0xc78a);
    }
}
