use crate::detect::{find_archive_start, RAR50_SIGNATURE};
use crate::error::{Error, Result};
use crate::rar15_40::crc32;
use crate::version::ArchiveFamily;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const HEAD_MAIN: u64 = 1;
const HEAD_FILE: u64 = 2;
const HEAD_SERVICE: u64 = 3;
const HEAD_CRYPT: u64 = 4;
const HEAD_END: u64 = 5;

const HFL_EXTRA: u64 = 0x0001;
const HFL_DATA: u64 = 0x0002;
const HFL_SPLIT_BEFORE: u64 = 0x0008;
const HFL_SPLIT_AFTER: u64 = 0x0010;

const MHFL_VOLUME: u64 = 0x0001;
const MHFL_VOLUME_NUMBER: u64 = 0x0002;
const MHFL_SOLID: u64 = 0x0004;
const MHFL_RECOVERY: u64 = 0x0008;
const MHFL_LOCKED: u64 = 0x0010;

const FHFL_DIRECTORY: u64 = 0x0001;
const FHFL_MTIME: u64 = 0x0002;
const FHFL_CRC32: u64 = 0x0004;

const FHEXTRA_CRYPT: u64 = 0x01;
const FHEXTRA_HASH: u64 = 0x02;

#[derive(Debug, Clone)]
pub struct Archive {
    pub sfx_offset: usize,
    pub main: MainHeader,
    pub blocks: Vec<Block>,
    source: ArchiveSource,
}

#[derive(Debug, Clone)]
enum ArchiveSource {
    Memory(Arc<[u8]>),
    File(Arc<PathBuf>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainHeader {
    pub block: BlockHeader,
    pub archive_flags: u64,
    pub volume_number: Option<u64>,
}

impl MainHeader {
    pub fn is_volume(&self) -> bool {
        self.archive_flags & MHFL_VOLUME != 0
    }

    pub fn is_solid(&self) -> bool {
        self.archive_flags & MHFL_SOLID != 0
    }

    pub fn has_recovery_record(&self) -> bool {
        self.archive_flags & MHFL_RECOVERY != 0
    }

    pub fn is_locked(&self) -> bool {
        self.archive_flags & MHFL_LOCKED != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    File(FileHeader),
    Service(FileHeader),
    End(BlockHeader),
    Unknown(BlockHeader),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub header_crc: u32,
    pub header_size: u64,
    pub header_type: u64,
    pub flags: u64,
    pub extra_area_size: Option<u64>,
    pub data_size: Option<u64>,
    pub offset: usize,
    pub header_range: Range<usize>,
    pub data_range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub block: BlockHeader,
    pub file_flags: u64,
    pub unpacked_size: u64,
    pub attributes: u64,
    pub mtime: Option<u32>,
    pub data_crc32: Option<u32>,
    pub compression_info: u64,
    pub host_os: u64,
    pub name: Vec<u8>,
    pub hash: Option<FileHash>,
    pub encrypted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHash {
    pub hash_type: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedEntry {
    pub name: Vec<u8>,
    pub data: Vec<u8>,
    pub file_time: u32,
    pub attr: u64,
    pub host_os: u64,
    pub is_directory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedEntryMeta {
    pub name: Vec<u8>,
    pub file_time: u32,
    pub attr: u64,
    pub host_os: u64,
    pub is_directory: bool,
}

impl FileHeader {
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }

    pub fn is_split_before(&self) -> bool {
        self.block.flags & HFL_SPLIT_BEFORE != 0
    }

    pub fn is_split_after(&self) -> bool {
        self.block.flags & HFL_SPLIT_AFTER != 0
    }

    pub fn is_directory(&self) -> bool {
        self.file_flags & FHFL_DIRECTORY != 0
    }

    pub fn is_stored(&self) -> bool {
        compression_method(self.compression_info) == 0
    }

    pub fn packed_size(&self) -> u64 {
        self.block.data_size.unwrap_or(0)
    }

    pub fn packed_data(&self, archive: &Archive) -> Result<Vec<u8>> {
        archive.read_range(self.block.data_range.clone())
    }

    pub fn verify_crc32(&self, data: &[u8]) -> Result<()> {
        let Some(expected) = self.data_crc32 else {
            return Ok(());
        };
        let actual = crc32(data);
        if actual == expected {
            Ok(())
        } else {
            Err(Error::Crc32Mismatch { expected, actual })
        }
    }

    pub fn metadata(&self) -> ExtractedEntryMeta {
        ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.mtime.unwrap_or(0),
            attr: self.attributes,
            host_os: self.host_os,
            is_directory: self.is_directory(),
        }
    }

    pub fn extract(&self, archive: &Archive) -> Result<ExtractedEntry> {
        if self.is_directory() {
            return Ok(ExtractedEntry {
                name: self.name.clone(),
                data: Vec::new(),
                file_time: self.mtime.unwrap_or(0),
                attr: self.attributes,
                host_os: self.host_os,
                is_directory: true,
            });
        }
        if self.encrypted {
            return Err(Error::NeedPassword);
        }
        if !self.is_stored() {
            return Err(Error::UnsupportedFeature {
                version: crate::version::ArchiveVersion::Rar50,
                feature: "RAR 5 compression",
            });
        }
        if self.packed_size() != self.unpacked_size {
            return Err(Error::InvalidHeader(
                "RAR 5 stored file has mismatched packed and unpacked sizes",
            ));
        }
        let data = self.packed_data(archive)?;
        self.verify_crc32(&data)?;
        Ok(ExtractedEntry {
            name: self.name.clone(),
            data,
            file_time: self.mtime.unwrap_or(0),
            attr: self.attributes,
            host_os: self.host_os,
            is_directory: false,
        })
    }

    fn write_stored_to(&self, archive: &Archive, out: &mut impl Write) -> Result<()> {
        if self.encrypted {
            return Err(Error::NeedPassword);
        }
        if !self.is_stored() {
            return Err(Error::UnsupportedFeature {
                version: crate::version::ArchiveVersion::Rar50,
                feature: "RAR 5 compression",
            });
        }
        if self.packed_size() != self.unpacked_size {
            return Err(Error::InvalidHeader(
                "RAR 5 stored file has mismatched packed and unpacked sizes",
            ));
        }
        let data = self.packed_data(archive)?;
        self.verify_crc32(&data)?;
        out.write_all(&data)?;
        Ok(())
    }
}

impl Archive {
    pub fn parse(input: &[u8]) -> Result<Self> {
        let data: Arc<[u8]> = Arc::from(input.to_vec().into_boxed_slice());
        Self::parse_shared(data)
    }

    pub fn parse_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = Arc::new(path.as_ref().to_path_buf());
        let mut file = File::open(path.as_ref())?;
        let len = file.metadata()?.len();
        let scan_len = len.min(128 * 1024) as usize;
        let mut scan = vec![0; scan_len];
        file.read_exact(&mut scan)?;
        let sig = find_archive_start(&scan, 128 * 1024).ok_or(Error::UnsupportedSignature)?;
        if sig.family != ArchiveFamily::Rar50Plus {
            return Err(Error::UnsupportedSignature);
        }
        let archive_len = usize::try_from(len)
            .map_err(|_| Error::InvalidHeader("RAR 5 archive size overflows usize"))?
            .checked_sub(sig.offset)
            .ok_or(Error::TooShort)?;
        Self::parse_file_backed(
            &mut file,
            archive_len,
            sig.offset,
            ArchiveSource::File(path),
        )
    }

    fn parse_shared(input: Arc<[u8]>) -> Result<Self> {
        let sig = find_archive_start(&input, 128 * 1024).ok_or(Error::UnsupportedSignature)?;
        if sig.family != ArchiveFamily::Rar50Plus {
            return Err(Error::UnsupportedSignature);
        }
        let archive = input.get(sig.offset..).ok_or(Error::TooShort)?;
        let mut parsed =
            Self::parse_seekable(archive.to_vec(), sig.offset, ArchiveSource::Memory(input))?;
        parsed.sfx_offset = sig.offset;
        Ok(parsed)
    }

    fn parse_seekable(input: Vec<u8>, sfx_offset: usize, source: ArchiveSource) -> Result<Self> {
        if !input.starts_with(RAR50_SIGNATURE) {
            return Err(Error::UnsupportedSignature);
        }

        let mut pos = RAR50_SIGNATURE.len();
        let first = parse_block_header(&input, pos, sfx_offset)?;
        if first.header_type == HEAD_CRYPT {
            return Err(Error::UnsupportedFeature {
                version: crate::version::ArchiveVersion::Rar50,
                feature: "RAR 5 encrypted headers",
            });
        }
        if first.header_type != HEAD_MAIN {
            return Err(Error::InvalidHeader("RAR 5 main header is missing"));
        }
        let main = parse_main_header(&input, first)?;
        pos = main.block.data_range.end - sfx_offset;

        let mut blocks = Vec::new();
        while pos < input.len() {
            let block = parse_block_header(&input, pos, sfx_offset)?;
            let next = block.data_range.end - sfx_offset;
            match block.header_type {
                HEAD_FILE => blocks.push(Block::File(parse_file_header(&input, block)?)),
                HEAD_SERVICE => blocks.push(Block::Service(parse_file_header(&input, block)?)),
                HEAD_CRYPT => {
                    return Err(Error::UnsupportedFeature {
                        version: crate::version::ArchiveVersion::Rar50,
                        feature: "RAR 5 encrypted headers",
                    });
                }
                HEAD_END => {
                    blocks.push(Block::End(block));
                    break;
                }
                _ => blocks.push(Block::Unknown(block)),
            }
            pos = next;
        }

        Ok(Self {
            sfx_offset,
            main,
            blocks,
            source,
        })
    }

    fn parse_file_backed(
        file: &mut File,
        archive_len: usize,
        sfx_offset: usize,
        source: ArchiveSource,
    ) -> Result<Self> {
        let signature = read_exact_at(file, sfx_offset, RAR50_SIGNATURE.len())?;
        if signature != RAR50_SIGNATURE {
            return Err(Error::UnsupportedSignature);
        }

        let mut pos = RAR50_SIGNATURE.len();
        let first = read_block_header_at(file, pos, archive_len, sfx_offset)?;
        if first.block.header_type == HEAD_CRYPT {
            return Err(Error::UnsupportedFeature {
                version: crate::version::ArchiveVersion::Rar50,
                feature: "RAR 5 encrypted headers",
            });
        }
        if first.block.header_type != HEAD_MAIN {
            return Err(Error::InvalidHeader("RAR 5 main header is missing"));
        }
        let main = parse_main_header_bytes(&first)?;
        pos = first.next_offset;

        let mut blocks = Vec::new();
        while pos < archive_len {
            let parsed = read_block_header_at(file, pos, archive_len, sfx_offset)?;
            let next = parsed.next_offset;
            match parsed.block.header_type {
                HEAD_FILE => blocks.push(Block::File(parse_file_header_bytes(&parsed)?)),
                HEAD_SERVICE => blocks.push(Block::Service(parse_file_header_bytes(&parsed)?)),
                HEAD_CRYPT => {
                    return Err(Error::UnsupportedFeature {
                        version: crate::version::ArchiveVersion::Rar50,
                        feature: "RAR 5 encrypted headers",
                    });
                }
                HEAD_END => {
                    blocks.push(Block::End(parsed.block));
                    break;
                }
                _ => blocks.push(Block::Unknown(parsed.block)),
            }
            pos = next;
        }

        Ok(Self {
            sfx_offset,
            main,
            blocks,
            source,
        })
    }

    fn read_range(&self, range: Range<usize>) -> Result<Vec<u8>> {
        match &self.source {
            ArchiveSource::Memory(data) => data
                .get(range)
                .map(|data| data.to_vec())
                .ok_or(Error::TooShort),
            ArchiveSource::File(path) => {
                let mut file = File::open(path.as_ref())?;
                read_exact_at(&mut file, range.start, range.len())
            }
        }
    }

    pub fn files(&self) -> impl Iterator<Item = &FileHeader> {
        self.blocks.iter().filter_map(|block| match block {
            Block::File(file) => Some(file),
            _ => None,
        })
    }

    pub fn services(&self) -> impl Iterator<Item = &FileHeader> {
        self.blocks.iter().filter_map(|block| match block {
            Block::Service(service) => Some(service),
            _ => None,
        })
    }

    pub fn extract(&self) -> Result<Vec<ExtractedEntry>> {
        let mut out = Vec::new();
        for file in self.files() {
            if file.is_split_before() || file.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 5 split entry requires multivolume extraction",
                ));
            }
            out.push(file.extract(self)?);
        }
        Ok(out)
    }

    pub fn extract_to<F>(&self, mut open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        for file in self.files() {
            if file.is_split_before() || file.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 5 split entry requires multivolume extraction",
                ));
            }
            let meta = file.metadata();
            let mut writer = open(&meta)?;
            if !meta.is_directory {
                file.write_stored_to(self, &mut writer)?;
            }
        }
        Ok(())
    }
}

fn parse_main_header(input: &[u8], block: BlockHeader) -> Result<MainHeader> {
    let mut reader = HeaderReader::new(input, block.header_range.clone())?;
    let archive_flags = reader.read_vint()?;
    let volume_number = if archive_flags & MHFL_VOLUME_NUMBER != 0 {
        Some(reader.read_vint()?)
    } else {
        None
    };
    Ok(MainHeader {
        block,
        archive_flags,
        volume_number,
    })
}

fn parse_main_header_bytes(parsed: &ParsedBlockHeader) -> Result<MainHeader> {
    let mut reader = HeaderReader::new(&parsed.header, parsed.type_specific_range.clone())?;
    let archive_flags = reader.read_vint()?;
    let volume_number = if archive_flags & MHFL_VOLUME_NUMBER != 0 {
        Some(reader.read_vint()?)
    } else {
        None
    };
    Ok(MainHeader {
        block: parsed.block.clone(),
        archive_flags,
        volume_number,
    })
}

fn parse_file_header(input: &[u8], block: BlockHeader) -> Result<FileHeader> {
    let mut reader = HeaderReader::new(input, block.header_range.clone())?;
    let file_flags = reader.read_vint()?;
    let unpacked_size = reader.read_vint()?;
    let attributes = reader.read_vint()?;
    let mtime = if file_flags & FHFL_MTIME != 0 {
        Some(reader.read_u32()?)
    } else {
        None
    };
    let data_crc32 = if file_flags & FHFL_CRC32 != 0 {
        Some(reader.read_u32()?)
    } else {
        None
    };
    let compression_info = reader.read_vint()?;
    let host_os = reader.read_vint()?;
    let name_len = usize_from_u64(
        reader.read_vint()?,
        "RAR 5 file name length overflows usize",
    )?;
    let name = reader.read_bytes(name_len)?.to_vec();
    let mut file = FileHeader {
        block,
        file_flags,
        unpacked_size,
        attributes,
        mtime,
        data_crc32,
        compression_info,
        host_os,
        name,
        hash: None,
        encrypted: false,
    };
    parse_file_extra(input, &mut file)?;
    Ok(file)
}

fn parse_file_header_bytes(parsed: &ParsedBlockHeader) -> Result<FileHeader> {
    let mut reader = HeaderReader::new(&parsed.header, parsed.type_specific_range.clone())?;
    let file_flags = reader.read_vint()?;
    let unpacked_size = reader.read_vint()?;
    let attributes = reader.read_vint()?;
    let mtime = if file_flags & FHFL_MTIME != 0 {
        Some(reader.read_u32()?)
    } else {
        None
    };
    let data_crc32 = if file_flags & FHFL_CRC32 != 0 {
        Some(reader.read_u32()?)
    } else {
        None
    };
    let compression_info = reader.read_vint()?;
    let host_os = reader.read_vint()?;
    let name_len = usize_from_u64(
        reader.read_vint()?,
        "RAR 5 file name length overflows usize",
    )?;
    let name = reader.read_bytes(name_len)?.to_vec();
    let mut file = FileHeader {
        block: parsed.block.clone(),
        file_flags,
        unpacked_size,
        attributes,
        mtime,
        data_crc32,
        compression_info,
        host_os,
        name,
        hash: None,
        encrypted: false,
    };
    parse_file_extra_area(&parsed.header, parsed.extra_range.clone(), &mut file)?;
    Ok(file)
}

fn parse_file_extra(input: &[u8], file: &mut FileHeader) -> Result<()> {
    let Some(extra_size) = file.block.extra_area_size else {
        return Ok(());
    };
    let extra_start = file.block.header_range.end;
    let extra_end = extra_start
        .checked_add(usize_from_u64(
            extra_size,
            "RAR 5 extra area size overflows usize",
        )?)
        .ok_or(Error::InvalidHeader(
            "RAR 5 extra area size overflows usize",
        ))?;
    if extra_end > input.len() {
        return Err(Error::TooShort);
    }
    parse_file_extra_area(input, extra_start..extra_end, file)
}

fn parse_file_extra_area(input: &[u8], range: Range<usize>, file: &mut FileHeader) -> Result<()> {
    if file.block.extra_area_size.is_none() {
        return Ok(());
    }
    let mut pos = range.start;
    while pos < range.end {
        let record_start = pos;
        let (record_size, size_len) = read_vint_at(input, pos, range.end)?;
        pos += size_len;
        let record_payload_len =
            usize_from_u64(record_size, "RAR 5 extra record size overflows usize")?;
        let record_end = pos
            .checked_add(record_payload_len)
            .ok_or(Error::InvalidHeader(
                "RAR 5 extra record size overflows usize",
            ))?;
        if record_end > range.end {
            return Err(Error::TooShort);
        }
        let (record_type, type_len) = read_vint_at(input, pos, record_end)?;
        let data_start = pos + type_len;
        match record_type {
            FHEXTRA_CRYPT => file.encrypted = true,
            FHEXTRA_HASH => {
                let (hash_type, hash_type_len) = read_vint_at(input, data_start, record_end)?;
                file.hash = Some(FileHash {
                    hash_type,
                    data: input[data_start + hash_type_len..record_end].to_vec(),
                });
            }
            _ => {}
        }
        if record_end <= record_start {
            return Err(Error::InvalidHeader("RAR 5 extra record does not advance"));
        }
        pos = record_end;
    }
    Ok(())
}

struct ParsedBlockHeader {
    block: BlockHeader,
    header: Vec<u8>,
    type_specific_range: Range<usize>,
    extra_range: Range<usize>,
    next_offset: usize,
}

fn read_block_header_at(
    file: &mut File,
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
) -> Result<ParsedBlockHeader> {
    let remaining = archive_len.checked_sub(offset).ok_or(Error::TooShort)?;
    if remaining < 5 {
        return Err(Error::TooShort);
    }
    let prefix_len = remaining.min(14);
    let prefix = read_exact_at(file, sfx_offset + offset, prefix_len)?;
    let header_crc = read_u32(&prefix, 0)?;
    let (header_size, header_size_len) = read_vint_at(&prefix, 4, prefix.len())?;
    let header_body_len = usize_from_u64(header_size, "RAR 5 header size overflows usize")?;
    let header_total = 4usize
        .checked_add(header_size_len)
        .and_then(|size| size.checked_add(header_body_len))
        .ok_or(Error::InvalidHeader("RAR 5 header size overflows usize"))?;
    if header_total > remaining {
        return Err(Error::TooShort);
    }

    let header = read_exact_at(file, sfx_offset + offset, header_total)?;
    let actual = crc32(&header[4..]);
    if actual != header_crc {
        return Err(Error::Crc32Mismatch {
            expected: header_crc,
            actual,
        });
    }

    let type_start = 4 + header_size_len;
    let mut reader = SliceReader::new(&header, type_start, header_total);
    let header_type = reader.read_vint()?;
    let flags = reader.read_vint()?;
    let extra_area_size = if flags & HFL_EXTRA != 0 {
        Some(reader.read_vint()?)
    } else {
        None
    };
    let data_size = if flags & HFL_DATA != 0 {
        Some(reader.read_vint()?)
    } else {
        None
    };
    let extra_len = extra_area_size
        .map(|size| usize_from_u64(size, "RAR 5 extra area size overflows usize"))
        .transpose()?
        .unwrap_or(0);
    if extra_len > header_total.saturating_sub(reader.pos) {
        return Err(Error::TooShort);
    }
    let type_specific_end = header_total - extra_len;
    let data_len = data_size
        .map(|size| usize_from_u64(size, "RAR 5 data size overflows usize"))
        .transpose()?
        .unwrap_or(0);
    let next_offset = offset
        .checked_add(header_total)
        .and_then(|pos| pos.checked_add(data_len))
        .ok_or(Error::InvalidHeader("RAR 5 data size overflows usize"))?;
    if next_offset > archive_len {
        return Err(Error::TooShort);
    }
    let type_specific_start = reader.pos;
    let data_start = sfx_offset
        .checked_add(offset)
        .and_then(|pos| pos.checked_add(header_total))
        .ok_or(Error::InvalidHeader("RAR 5 data offset overflows usize"))?;
    let data_end = data_start
        .checked_add(data_len)
        .ok_or(Error::InvalidHeader("RAR 5 data size overflows usize"))?;

    Ok(ParsedBlockHeader {
        block: BlockHeader {
            header_crc,
            header_size,
            header_type,
            flags,
            extra_area_size,
            data_size,
            offset: sfx_offset + offset,
            header_range: (offset + type_specific_start)..(offset + type_specific_end),
            data_range: data_start..data_end,
        },
        header,
        type_specific_range: type_specific_start..type_specific_end,
        extra_range: type_specific_end..header_total,
        next_offset,
    })
}

fn parse_block_header(input: &[u8], offset: usize, sfx_offset: usize) -> Result<BlockHeader> {
    let header_crc = read_u32(input, offset)?;
    let after_crc = offset + 4;
    let (header_size, header_size_len) = read_vint_at(input, after_crc, input.len())?;
    let type_start = after_crc + header_size_len;
    let header_body_len = usize_from_u64(header_size, "RAR 5 header size overflows usize")?;
    let header_end = type_start
        .checked_add(header_body_len)
        .ok_or(Error::InvalidHeader("RAR 5 header size overflows usize"))?;
    if header_end > input.len() {
        return Err(Error::TooShort);
    }
    let actual = crc32(&input[after_crc..header_end]);
    if actual != header_crc {
        return Err(Error::Crc32Mismatch {
            expected: header_crc,
            actual,
        });
    }

    let mut reader = SliceReader::new(input, type_start, header_end);
    let header_type = reader.read_vint()?;
    let flags = reader.read_vint()?;
    let extra_area_size = if flags & HFL_EXTRA != 0 {
        Some(reader.read_vint()?)
    } else {
        None
    };
    let data_size = if flags & HFL_DATA != 0 {
        Some(reader.read_vint()?)
    } else {
        None
    };
    let extra_len = extra_area_size
        .map(|size| usize_from_u64(size, "RAR 5 extra area size overflows usize"))
        .transpose()?
        .unwrap_or(0);
    if extra_len > header_end.saturating_sub(reader.pos) {
        return Err(Error::TooShort);
    }
    let type_specific_end = header_end - extra_len;
    let data_start = sfx_offset
        .checked_add(header_end)
        .ok_or(Error::InvalidHeader("RAR 5 data offset overflows usize"))?;
    let data_len = data_size
        .map(|size| usize_from_u64(size, "RAR 5 data size overflows usize"))
        .transpose()?
        .unwrap_or(0);
    let data_end = data_start
        .checked_add(data_len)
        .ok_or(Error::InvalidHeader("RAR 5 data size overflows usize"))?;
    if header_end + data_len > input.len() {
        return Err(Error::TooShort);
    }

    Ok(BlockHeader {
        header_crc,
        header_size,
        header_type,
        flags,
        extra_area_size,
        data_size,
        offset: sfx_offset + offset,
        header_range: reader.pos..type_specific_end,
        data_range: data_start..data_end,
    })
}

struct HeaderReader<'a> {
    input: &'a [u8],
    range: Range<usize>,
    pos: usize,
}

impl<'a> HeaderReader<'a> {
    fn new(input: &'a [u8], range: Range<usize>) -> Result<Self> {
        if range.end > input.len() {
            return Err(Error::TooShort);
        }
        Ok(Self {
            input,
            pos: range.start,
            range,
        })
    }

    fn read_vint(&mut self) -> Result<u64> {
        let (value, len) = read_vint_at(self.input, self.pos, self.range.end)?;
        self.pos += len;
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let value = read_u32(self.input, self.pos)?;
        self.pos += 4;
        Ok(value)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(Error::InvalidHeader("RAR 5 field size overflows usize"))?;
        if end > self.range.end {
            return Err(Error::TooShort);
        }
        let bytes = &self.input[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }
}

struct SliceReader<'a> {
    input: &'a [u8],
    end: usize,
    pos: usize,
}

impl<'a> SliceReader<'a> {
    fn new(input: &'a [u8], pos: usize, end: usize) -> Self {
        Self { input, pos, end }
    }

    fn read_vint(&mut self) -> Result<u64> {
        let (value, len) = read_vint_at(self.input, self.pos, self.end)?;
        self.pos += len;
        Ok(value)
    }
}

fn read_vint_at(input: &[u8], offset: usize, end: usize) -> Result<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for i in 0..10 {
        let byte = *input.get(offset + i).ok_or(Error::TooShort)?;
        if offset + i >= end {
            return Err(Error::TooShort);
        }
        value = value
            .checked_add(((byte & 0x7f) as u64) << shift)
            .ok_or(Error::InvalidHeader("RAR 5 vint overflows u64"))?;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(Error::InvalidHeader("RAR 5 vint is too long"))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32> {
    let bytes = input.get(offset..offset + 4).ok_or(Error::TooShort)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_exact_at(file: &mut File, offset: usize, len: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset as u64))?;
    let mut bytes = vec![0; len];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn usize_from_u64(value: u64, message: &'static str) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::InvalidHeader(message))
}

fn compression_method(compression_info: u64) -> u64 {
    (compression_info >> 7) & 0x07
}
