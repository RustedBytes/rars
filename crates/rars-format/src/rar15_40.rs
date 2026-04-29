use crate::detect::{find_archive_start, RAR15_SIGNATURE};
use crate::error::{Error, Result};
use crate::version::ArchiveFamily;
use rars_codec::rar29::Unpack29;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const MARK_HEAD: u8 = 0x72;
const MAIN_HEAD: u8 = 0x73;
const FILE_HEAD: u8 = 0x74;
const NEWSUB_HEAD: u8 = 0x7a;
const ENDARC_HEAD: u8 = 0x7b;

const LONG_BLOCK: u16 = 0x8000;
const MHD_VOLUME: u16 = 0x0001;
const MHD_SOLID: u16 = 0x0008;
const MHD_NEWNUMBERING: u16 = 0x0010;
const MHD_PROTECT: u16 = 0x0040;
const MHD_PASSWORD: u16 = 0x0080;
const MHD_FIRSTVOLUME: u16 = 0x0100;
const MHD_ENCRYPTVER: u16 = 0x0200;

const FHD_SPLIT_BEFORE: u16 = 0x0001;
const FHD_SPLIT_AFTER: u16 = 0x0002;
const FHD_PASSWORD: u16 = 0x0004;
const FHD_SOLID: u16 = 0x0010;
const FHD_LARGE: u16 = 0x0100;
const FHD_SALT: u16 = 0x0400;
const FHD_EXTTIME: u16 = 0x1000;
const FHD_DIRECTORY_MASK: u16 = 0x00e0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Archive {
    pub sfx_offset: usize,
    pub main: MainHeader,
    pub blocks: Vec<Block>,
    source: ArchiveSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ArchiveSource {
    Memory(Arc<[u8]>),
    File(Arc<PathBuf>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainHeader {
    pub head_crc: u16,
    pub flags: u16,
    pub head_size: u16,
    pub reserved1: u16,
    pub reserved2: u32,
    pub encrypt_version: Option<u8>,
}

impl MainHeader {
    pub fn is_volume(&self) -> bool {
        self.flags & MHD_VOLUME != 0
    }

    pub fn is_solid(&self) -> bool {
        self.flags & MHD_SOLID != 0
    }

    pub fn uses_new_numbering(&self) -> bool {
        self.flags & MHD_NEWNUMBERING != 0
    }

    pub fn has_recovery_record(&self) -> bool {
        self.flags & MHD_PROTECT != 0
    }

    pub fn has_encrypted_headers(&self) -> bool {
        self.flags & MHD_PASSWORD != 0
    }

    pub fn is_first_volume(&self) -> bool {
        self.flags & MHD_FIRSTVOLUME != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    File(FileHeader),
    NewSub(NewSubHeader),
    End(BlockHeader),
    Unknown(BlockHeader),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub head_crc: u16,
    pub head_type: u8,
    pub flags: u16,
    pub head_size: u16,
    pub add_size: Option<u64>,
    pub offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub block: BlockHeader,
    pub pack_size: u64,
    pub unp_size: u64,
    pub host_os: u8,
    pub file_crc: u32,
    pub file_time: u32,
    pub unp_ver: u8,
    pub method: u8,
    pub name: Vec<u8>,
    pub attr: u32,
    pub salt: Option<[u8; 8]>,
    pub ext_time: Vec<u8>,
    pub packed_range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSubHeader {
    pub file: FileHeader,
    pub kind: NewSubKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewSubKind {
    ArchiveComment,
    RecoveryRecord,
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedEntry {
    pub name: Vec<u8>,
    pub data: Vec<u8>,
    pub file_time: u32,
    pub attr: u32,
    pub host_os: u8,
    pub is_directory: bool,
}

#[derive(Debug)]
struct PendingSplit {
    name: Vec<u8>,
    data: Vec<u8>,
    file_time: u32,
    attr: u32,
    host_os: u8,
    method: u8,
    encrypted: bool,
}

impl FileHeader {
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }

    pub fn is_split_before(&self) -> bool {
        self.block.flags & FHD_SPLIT_BEFORE != 0
    }

    pub fn is_split_after(&self) -> bool {
        self.block.flags & FHD_SPLIT_AFTER != 0
    }

    pub fn is_encrypted(&self) -> bool {
        self.block.flags & FHD_PASSWORD != 0
    }

    pub fn is_solid(&self) -> bool {
        self.block.flags & FHD_SOLID != 0
    }

    pub fn is_directory(&self) -> bool {
        self.block.flags & FHD_DIRECTORY_MASK == FHD_DIRECTORY_MASK
    }

    pub fn has_ext_time(&self) -> bool {
        self.block.flags & FHD_EXTTIME != 0
    }

    pub fn is_stored(&self) -> bool {
        self.method == 0x30
    }

    pub fn packed_data(&self, archive: &Archive) -> Result<Vec<u8>> {
        archive.read_range(self.packed_range.clone())
    }

    pub fn write_packed_data(&self, archive: &Archive, out: &mut impl Write) -> Result<()> {
        archive.copy_range_to(self.packed_range.clone(), out)
    }

    pub fn stored_data(&self, archive: &Archive) -> Result<Vec<u8>> {
        if self.is_encrypted() {
            return Err(Error::InvalidHeader(
                "RAR 1.5 encrypted file extraction is not implemented",
            ));
        }
        if !self.is_stored() {
            return Err(Error::InvalidHeader(
                "RAR 1.5 compressed file extraction is not implemented",
            ));
        }
        if self.pack_size != self.unp_size {
            return Err(Error::InvalidHeader(
                "RAR 1.5 stored file has mismatched packed and unpacked sizes",
            ));
        }
        self.packed_data(archive)
    }

    pub fn unpacked_data(&self, archive: &Archive) -> Result<Vec<u8>> {
        if self.is_stored() {
            return self.stored_data(archive);
        }
        if self.is_encrypted() {
            return Err(Error::InvalidHeader(
                "RAR 1.5 encrypted file extraction is not implemented",
            ));
        }
        if self.unp_ver >= 29 {
            let mut decoder = Unpack29::new();
            return self.unpacked_data_with_rar29(archive, &mut decoder);
        }
        Err(Error::InvalidHeader(
            "RAR 1.5 compressed file extraction is not implemented",
        ))
    }

    pub fn unpacked_data_with_rar29(
        &self,
        archive: &Archive,
        decoder: &mut Unpack29,
    ) -> Result<Vec<u8>> {
        if self.is_stored() {
            return self.stored_data(archive);
        }
        if self.is_encrypted() {
            return Err(Error::InvalidHeader(
                "RAR 1.5 encrypted file extraction is not implemented",
            ));
        }
        if self.unp_ver < 29 {
            return Err(Error::InvalidHeader(
                "RAR 1.5 compressed file extraction is not implemented",
            ));
        }
        decoder
            .decode_member(
                &self.packed_data(archive)?,
                usize::try_from(self.unp_size)
                    .map_err(|_| Error::InvalidHeader("RAR 2.9 unpacked size overflows usize"))?,
            )
            .map_err(Into::into)
    }

    pub fn verify_crc32(&self, data: &[u8]) -> Result<()> {
        let actual = crc32(data);
        if actual == self.file_crc {
            Ok(())
        } else {
            Err(Error::Crc32Mismatch {
                expected: self.file_crc,
                actual,
            })
        }
    }

    pub fn extract_stored(&self, archive: &Archive) -> Result<ExtractedEntry> {
        if self.is_directory() {
            return Ok(ExtractedEntry {
                name: self.name.clone(),
                data: Vec::new(),
                file_time: self.file_time,
                attr: self.attr,
                host_os: self.host_os,
                is_directory: true,
            });
        }

        let data = self.stored_data(archive)?;
        self.verify_crc32(&data)?;
        Ok(ExtractedEntry {
            name: self.name.clone(),
            data,
            file_time: self.file_time,
            attr: self.attr,
            host_os: self.host_os,
            is_directory: false,
        })
    }

    pub fn extract(&self, archive: &Archive) -> Result<ExtractedEntry> {
        if self.is_directory() {
            return Ok(ExtractedEntry {
                name: self.name.clone(),
                data: Vec::new(),
                file_time: self.file_time,
                attr: self.attr,
                host_os: self.host_os,
                is_directory: true,
            });
        }

        let data = self.unpacked_data(archive)?;
        self.verify_crc32(&data)?;
        Ok(ExtractedEntry {
            name: self.name.clone(),
            data,
            file_time: self.file_time,
            attr: self.attr,
            host_os: self.host_os,
            is_directory: false,
        })
    }
}

impl NewSubHeader {
    pub fn name_lossy(&self) -> String {
        self.file.name_lossy()
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
        if sig.family != ArchiveFamily::Rar15To40 {
            return Err(Error::UnsupportedSignature);
        }
        Self::parse_seekable(file, len, sig.offset, ArchiveSource::File(path))
    }

    fn parse_shared(input: Arc<[u8]>) -> Result<Self> {
        let sig = find_archive_start(&input, 128 * 1024).ok_or(Error::UnsupportedSignature)?;
        if sig.family != ArchiveFamily::Rar15To40 {
            return Err(Error::UnsupportedSignature);
        }

        let archive = &input[sig.offset..];
        if !archive.starts_with(RAR15_SIGNATURE) {
            return Err(Error::UnsupportedSignature);
        }

        let marker = parse_block_header(archive, 0)?;
        if marker.head_type != MARK_HEAD || marker.head_size != RAR15_SIGNATURE.len() as u16 {
            return Err(Error::InvalidHeader("RAR 1.5 marker block is invalid"));
        }

        let main_block = parse_block_header(archive, marker.head_size as usize)?;
        if main_block.head_type != MAIN_HEAD {
            return Err(Error::InvalidHeader("RAR 1.5 main header is missing"));
        }
        let main = parse_main_header(archive, &main_block)?;
        let mut pos = main_block.offset + main_block.head_size as usize;
        let mut blocks = Vec::new();

        while pos < archive.len() {
            if archive.len() - pos < 7 {
                break;
            }
            let block = parse_block_header(archive, pos)?;
            let total = block_total_size(&block)?;
            let next = block
                .offset
                .checked_add(total)
                .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
            if next > archive.len() {
                return Err(Error::TooShort);
            }

            match block.head_type {
                FILE_HEAD => blocks.push(Block::File(parse_file_like_header(
                    archive, block, sig.offset,
                )?)),
                NEWSUB_HEAD => {
                    let file = parse_file_like_header(archive, block, sig.offset)?;
                    let kind = classify_new_sub(&file.name);
                    blocks.push(Block::NewSub(NewSubHeader { file, kind }));
                }
                ENDARC_HEAD => {
                    blocks.push(Block::End(block));
                    break;
                }
                _ => blocks.push(Block::Unknown(block)),
            }
            pos = next;
        }

        Ok(Self {
            sfx_offset: sig.offset,
            main,
            blocks,
            source: ArchiveSource::Memory(input),
        })
    }

    fn parse_seekable(
        mut file: File,
        file_len: u64,
        sfx_offset: usize,
        source: ArchiveSource,
    ) -> Result<Self> {
        let marker = read_block_header_at(&mut file, file_len, sfx_offset, 0)?;
        if marker.head_type != MARK_HEAD || marker.head_size != RAR15_SIGNATURE.len() as u16 {
            return Err(Error::InvalidHeader("RAR 1.5 marker block is invalid"));
        }

        let main_block =
            read_block_header_at(&mut file, file_len, sfx_offset, marker.head_size as usize)?;
        if main_block.head_type != MAIN_HEAD {
            return Err(Error::InvalidHeader("RAR 1.5 main header is missing"));
        }
        let main_header = read_exact_at(
            &mut file,
            sfx_offset + main_block.offset,
            main_block.head_size as usize,
        )?;
        let main = parse_main_header(&main_header, &relative_block(&main_block))?;
        let mut pos = main_block.offset + main_block.head_size as usize;
        let mut blocks = Vec::new();

        while (sfx_offset + pos) as u64 + 7 <= file_len {
            let block = read_block_header_at(&mut file, file_len, sfx_offset, pos)?;
            let total = block_total_size(&block)?;
            let next = block
                .offset
                .checked_add(total)
                .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
            if (sfx_offset + next) as u64 > file_len {
                return Err(Error::TooShort);
            }

            match block.head_type {
                FILE_HEAD => blocks.push(Block::File(read_file_like_header(
                    &mut file, file_len, sfx_offset, block,
                )?)),
                NEWSUB_HEAD => {
                    let file_header =
                        read_file_like_header(&mut file, file_len, sfx_offset, block)?;
                    let kind = classify_new_sub(&file_header.name);
                    blocks.push(Block::NewSub(NewSubHeader {
                        file: file_header,
                        kind,
                    }));
                }
                ENDARC_HEAD => {
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

    fn copy_range_to(&self, range: Range<usize>, out: &mut impl Write) -> Result<()> {
        match &self.source {
            ArchiveSource::Memory(data) => {
                let data = data.get(range).ok_or(Error::TooShort)?;
                out.write_all(data)?;
            }
            ArchiveSource::File(path) => {
                let mut file = File::open(path.as_ref())?;
                file.seek(SeekFrom::Start(range.start as u64))?;
                let mut limited = file.take(range.len() as u64);
                std::io::copy(&mut limited, out)?;
            }
        }
        Ok(())
    }

    pub fn files(&self) -> impl Iterator<Item = &FileHeader> {
        self.blocks.iter().filter_map(|block| match block {
            Block::File(file) => Some(file),
            _ => None,
        })
    }

    pub fn new_subs(&self) -> impl Iterator<Item = &NewSubHeader> {
        self.blocks.iter().filter_map(|block| match block {
            Block::NewSub(sub) => Some(sub),
            _ => None,
        })
    }

    pub fn extract_stored(&self) -> Result<Vec<ExtractedEntry>> {
        if self.main.has_encrypted_headers() {
            return Err(Error::InvalidHeader(
                "RAR 1.5 encrypted header extraction is not implemented",
            ));
        }

        let mut out = Vec::new();
        for file in self.files() {
            if file.is_split_before() || file.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 split entry requires multivolume extraction",
                ));
            }
            out.push(file.extract_stored(self)?);
        }
        Ok(out)
    }

    pub fn extract(&self) -> Result<Vec<ExtractedEntry>> {
        if self.main.has_encrypted_headers() {
            return Err(Error::InvalidHeader(
                "RAR 1.5 encrypted header extraction is not implemented",
            ));
        }

        let mut out = Vec::new();
        let mut rar29 = Unpack29::new();
        let shared_rar29 = self.main.is_solid();
        for file in self.files() {
            if file.is_split_before() || file.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 split entry requires multivolume extraction",
                ));
            }
            if shared_rar29 && !file.is_stored() {
                out.push(extract_with_rar29(self, file, &mut rar29)?);
            } else {
                rar29 = Unpack29::new();
                out.push(file.extract(self)?);
            }
        }
        Ok(out)
    }

    pub fn archive_comment(&self) -> Result<Option<Vec<u8>>> {
        let Some(comment) = self
            .new_subs()
            .find(|sub| sub.kind == NewSubKind::ArchiveComment)
        else {
            return Ok(None);
        };
        let data = comment.file.unpacked_data(self)?;
        comment.file.verify_crc32(&data)?;
        Ok(Some(data))
    }
}

fn extract_with_rar29(
    archive: &Archive,
    file: &FileHeader,
    decoder: &mut Unpack29,
) -> Result<ExtractedEntry> {
    if file.is_directory() {
        return Ok(ExtractedEntry {
            name: file.name.clone(),
            data: Vec::new(),
            file_time: file.file_time,
            attr: file.attr,
            host_os: file.host_os,
            is_directory: true,
        });
    }
    let data = file.unpacked_data_with_rar29(archive, decoder)?;
    file.verify_crc32(&data)?;
    Ok(ExtractedEntry {
        name: file.name.clone(),
        data,
        file_time: file.file_time,
        attr: file.attr,
        host_os: file.host_os,
        is_directory: false,
    })
}

pub fn extract_volumes(volumes: &[Archive]) -> Result<Vec<ExtractedEntry>> {
    if volumes.is_empty() {
        return Err(Error::InvalidHeader("RAR 1.5 volume set is empty"));
    }

    let mut out = Vec::new();
    let mut pending: Option<PendingSplit> = None;
    for archive in volumes {
        if archive.main.has_encrypted_headers() {
            return Err(Error::InvalidHeader(
                "RAR 1.5 encrypted header extraction is not implemented",
            ));
        }

        for file in archive.files() {
            match (
                pending.is_some(),
                file.is_split_before(),
                file.is_split_after(),
            ) {
                (false, false, false) => out.push(file.extract(archive)?),
                (false, false, true) => {
                    validate_split_fragment(file)?;
                    pending = Some(PendingSplit {
                        name: file.name.clone(),
                        data: file.packed_data(archive)?.to_vec(),
                        file_time: file.file_time,
                        attr: file.attr,
                        host_os: file.host_os,
                        method: file.method,
                        encrypted: file.is_encrypted(),
                    });
                }
                (true, true, true) => {
                    let current = pending.as_mut().expect("pending split");
                    validate_split_continuation(current, file)?;
                    current.data.extend_from_slice(&file.packed_data(archive)?);
                }
                (true, true, false) => {
                    let mut completed = pending.take().expect("pending split");
                    validate_split_continuation(&completed, file)?;
                    completed
                        .data
                        .extend_from_slice(&file.packed_data(archive)?);
                    let data = if completed.method == 0x30 {
                        let expected_len = usize::try_from(file.unp_size).map_err(|_| {
                            Error::InvalidHeader("RAR 1.5 split unpacked size overflows usize")
                        })?;
                        if completed.data.len() != expected_len {
                            return Err(Error::InvalidHeader(
                                "RAR 1.5 split stored file has wrong reassembled size",
                            ));
                        }
                        completed.data
                    } else if file.unp_ver >= 29 {
                        let mut decoder = Unpack29::new();
                        decoder
                            .decode_member(
                                &completed.data,
                                usize::try_from(file.unp_size).map_err(|_| {
                                    Error::InvalidHeader(
                                        "RAR 2.9 split unpacked size overflows usize",
                                    )
                                })?,
                            )
                            .map_err(Error::from)?
                    } else {
                        return Err(Error::InvalidHeader(
                            "RAR 1.5 compressed file extraction is not implemented",
                        ));
                    };
                    file.verify_crc32(&data)?;
                    out.push(ExtractedEntry {
                        name: completed.name,
                        data,
                        file_time: completed.file_time,
                        attr: completed.attr,
                        host_os: completed.host_os,
                        is_directory: false,
                    });
                }
                (false, true, _) => {
                    return Err(Error::InvalidHeader(
                        "RAR 1.5 split entry is missing its first part",
                    ));
                }
                (true, false, _) => {
                    return Err(Error::InvalidHeader(
                        "RAR 1.5 split entry is interrupted by a regular entry",
                    ));
                }
            }
        }
    }

    if pending.is_some() {
        return Err(Error::InvalidHeader("RAR 1.5 split entry is incomplete"));
    }

    Ok(out)
}

fn validate_split_fragment(file: &FileHeader) -> Result<()> {
    if file.is_directory() {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split directory entry is invalid",
        ));
    }
    if file.is_encrypted() {
        return Err(Error::InvalidHeader(
            "RAR 1.5 encrypted file extraction is not implemented",
        ));
    }
    if !file.is_stored() {
        return Err(Error::InvalidHeader(
            "RAR 1.5 compressed file extraction is not implemented",
        ));
    }
    Ok(())
}

fn validate_split_continuation(pending: &PendingSplit, file: &FileHeader) -> Result<()> {
    validate_split_fragment(file)?;
    if file.name != pending.name {
        return Err(Error::InvalidHeader("RAR 1.5 split entry name changed"));
    }
    if file.method != pending.method {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split entry compression method changed",
        ));
    }
    if file.is_encrypted() != pending.encrypted {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split entry encryption flag changed",
        ));
    }
    Ok(())
}

fn classify_new_sub(name: &[u8]) -> NewSubKind {
    match name {
        b"CMT" => NewSubKind::ArchiveComment,
        b"RR" => NewSubKind::RecoveryRecord,
        _ => NewSubKind::Unknown(name.to_vec()),
    }
}

fn parse_main_header(input: &[u8], block: &BlockHeader) -> Result<MainHeader> {
    if block.head_size < 13 {
        return Err(Error::InvalidHeader("RAR 1.5 main header is too short"));
    }
    let start = block.offset;
    let head_end = start + block.head_size as usize;
    if head_end > input.len() {
        return Err(Error::TooShort);
    }

    let encrypt_version = if block.flags & MHD_ENCRYPTVER != 0 {
        Some(*input.get(start + 13).ok_or(Error::TooShort)?)
    } else {
        None
    };

    Ok(MainHeader {
        head_crc: block.head_crc,
        flags: block.flags,
        head_size: block.head_size,
        reserved1: read_u16(input, start + 7)?,
        reserved2: read_u32(input, start + 9)?,
        encrypt_version,
    })
}

fn parse_file_like_header(
    input: &[u8],
    block: BlockHeader,
    archive_offset: usize,
) -> Result<FileHeader> {
    if block.head_size < 32 {
        return Err(Error::InvalidHeader("RAR 1.5 file header is too short"));
    }
    if block.flags & LONG_BLOCK == 0 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 file header is missing packed data size",
        ));
    }

    let start = block.offset;
    let head_end = start + block.head_size as usize;
    if head_end > input.len() {
        return Err(Error::TooShort);
    }

    let pack_low = read_u32(input, start + 7)? as u64;
    let unp_low = read_u32(input, start + 11)? as u64;
    let host_os = input[start + 15];
    let file_crc = read_u32(input, start + 16)?;
    let file_time = read_u32(input, start + 20)?;
    let unp_ver = input[start + 24];
    let method = input[start + 25];
    let name_size = read_u16(input, start + 26)? as usize;
    let attr = read_u32(input, start + 28)?;
    let mut pos = start + 32;

    let (pack_size, unp_size) = if block.flags & FHD_LARGE != 0 {
        let high_pack = read_u32(input, pos)? as u64;
        let high_unp = read_u32(input, pos + 4)? as u64;
        pos += 8;
        ((high_pack << 32) | pack_low, (high_unp << 32) | unp_low)
    } else {
        (pack_low, unp_low)
    };

    let name_end = pos
        .checked_add(name_size)
        .ok_or(Error::InvalidHeader("RAR 1.5 file name size overflows"))?;
    if name_end > head_end {
        return Err(Error::InvalidHeader(
            "RAR 1.5 file name extends beyond header",
        ));
    }
    let name = input[pos..name_end].to_vec();
    pos = name_end;

    let salt = if block.flags & FHD_SALT != 0 {
        let salt_bytes = input.get(pos..pos + 8).ok_or(Error::TooShort)?;
        pos += 8;
        Some(
            salt_bytes
                .try_into()
                .expect("RAR 1.5 salt slice has fixed length"),
        )
    } else {
        None
    };

    let ext_time = if block.flags & FHD_EXTTIME != 0 {
        input[pos..head_end].to_vec()
    } else {
        Vec::new()
    };
    let data_start = head_end;
    let data_len = usize::try_from(pack_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 packed file size overflows usize"))?;
    let data_end = data_start
        .checked_add(data_len)
        .ok_or(Error::InvalidHeader(
            "RAR 1.5 packed file size overflows usize",
        ))?;
    Ok(FileHeader {
        block,
        pack_size,
        unp_size,
        host_os,
        file_crc,
        file_time,
        unp_ver,
        method,
        name,
        attr,
        salt,
        ext_time,
        packed_range: archive_offset + data_start..archive_offset + data_end,
    })
}

fn read_file_like_header(
    file: &mut File,
    file_len: u64,
    archive_offset: usize,
    block: BlockHeader,
) -> Result<FileHeader> {
    let header = read_exact_at(
        file,
        archive_offset + block.offset,
        block.head_size as usize,
    )?;
    let relative = relative_block(&block);
    let data_start = archive_offset + block.offset + block.head_size as usize;
    let data_end = data_start
        .checked_add(
            usize::try_from(block.add_size.unwrap_or(0))
                .map_err(|_| Error::InvalidHeader("RAR 1.5 packed file size overflows usize"))?,
        )
        .ok_or(Error::InvalidHeader(
            "RAR 1.5 packed file size overflows usize",
        ))?;
    if data_end as u64 > file_len {
        return Err(Error::TooShort);
    }
    parse_file_like_header(&header, relative, archive_offset + block.offset)
}

fn read_block_header_at(
    file: &mut File,
    file_len: u64,
    archive_offset: usize,
    offset: usize,
) -> Result<BlockHeader> {
    let absolute = archive_offset
        .checked_add(offset)
        .ok_or(Error::InvalidHeader("RAR 1.5 block offset overflows usize"))?;
    if absolute as u64 + 7 > file_len {
        return Err(Error::TooShort);
    }
    let base = read_exact_at(file, absolute, 7)?;
    let head_size = read_u16(&base, 5)? as usize;
    if head_size < 7 {
        return Err(Error::InvalidHeader("RAR 1.5 block header is too short"));
    }
    if absolute as u64 + head_size as u64 > file_len {
        return Err(Error::TooShort);
    }
    let header = if head_size == 7 {
        base
    } else {
        read_exact_at(file, absolute, head_size)?
    };
    let mut block = parse_block_header(&header, 0)?;
    block.offset = offset;
    Ok(block)
}

fn read_exact_at(file: &mut File, offset: usize, len: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset as u64))?;
    let mut data = vec![0; len];
    file.read_exact(&mut data)?;
    Ok(data)
}

fn relative_block(block: &BlockHeader) -> BlockHeader {
    let mut relative = block.clone();
    relative.offset = 0;
    relative
}

fn parse_block_header(input: &[u8], offset: usize) -> Result<BlockHeader> {
    if input.len() < offset + 7 {
        return Err(Error::TooShort);
    }
    let head_crc = read_u16(input, offset)?;
    let head_type = input[offset + 2];
    let flags = read_u16(input, offset + 3)?;
    let head_size = read_u16(input, offset + 5)?;
    if head_size < 7 {
        return Err(Error::InvalidHeader("RAR 1.5 block header is too short"));
    }
    let add_size = if flags & LONG_BLOCK != 0 {
        Some(read_u32(input, offset + 7)? as u64)
    } else {
        None
    };
    if offset + head_size as usize > input.len() {
        return Err(Error::TooShort);
    }
    if head_type != MARK_HEAD && should_validate_header_crc(head_type) {
        let header_end = offset + head_size as usize;
        let actual = (crc32(&input[offset + 2..header_end]) & 0xffff) as u16;
        if actual != head_crc {
            return Err(Error::CrcMismatch {
                expected: head_crc,
                actual,
            });
        }
    }

    Ok(BlockHeader {
        head_crc,
        head_type,
        flags,
        head_size,
        add_size,
        offset,
    })
}

fn should_validate_header_crc(head_type: u8) -> bool {
    // Historical AV/SIGN blocks are documented with inconsistent CRC fields in
    // real archives, so readers must not reject them solely on HEAD_CRC.
    !matches!(head_type, 0x76 | 0x79)
}

fn block_total_size(block: &BlockHeader) -> Result<usize> {
    let total = block.head_size as u64 + block.add_size.unwrap_or(0);
    usize::try_from(total).map_err(|_| Error::InvalidHeader("RAR 1.5 block size overflows usize"))
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16> {
    let bytes = input.get(offset..offset + 2).ok_or(Error::TooShort)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32> {
    let bytes = input.get(offset..offset + 4).ok_or(Error::TooShort)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub fn crc32(input: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in input {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
