use crate::detect::{find_archive_start, RAR15_SIGNATURE};
use crate::error::{Error, Result};
use crate::features::FeatureSet;
use crate::version::ArchiveFamily;
use crate::ArchiveVersion;
use rars_codec::rar13::{unpack15_encode, Unpack15, Unpack15Encoder};
use rars_codec::rar20::Unpack20;
use rars_codec::rar29::Unpack29;
use rars_crypto::rar15::Rar15Cipher;
use rars_crypto::rar20::Rar20Cipher;
use rars_crypto::rar30::Rar30Cipher;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod extract;
use extract::DecoderSession;
pub use extract::{
    extract_volumes, extract_volumes_to, extract_volumes_to_with_password,
    extract_volumes_with_password,
};

const MARK_HEAD: u8 = 0x72;
const MAIN_HEAD: u8 = 0x73;
const FILE_HEAD: u8 = 0x74;
const COMM_HEAD: u8 = 0x75;
const NEWSUB_HEAD: u8 = 0x7a;
const ENDARC_HEAD: u8 = 0x7b;

const LONG_BLOCK: u16 = 0x8000;
const MHD_VOLUME: u16 = 0x0001;
const MHD_COMMENT: u16 = 0x0002;
const MHD_SOLID: u16 = 0x0008;
const MHD_NEWNUMBERING: u16 = 0x0010;
const MHD_PROTECT: u16 = 0x0040;
const MHD_PASSWORD: u16 = 0x0080;
const MHD_FIRSTVOLUME: u16 = 0x0100;
const MHD_ENCRYPTVER: u16 = 0x0200;

const FHD_SPLIT_BEFORE: u16 = 0x0001;
const FHD_SPLIT_AFTER: u16 = 0x0002;
const FHD_PASSWORD: u16 = 0x0004;
const FHD_COMMENT: u16 = 0x0008;
const FHD_SOLID: u16 = 0x0010;
const FHD_LARGE: u16 = 0x0100;
const FHD_UNICODE: u16 = 0x0200;
const FHD_SALT: u16 = 0x0400;
const FHD_EXTTIME: u16 = 0x1000;
const FHD_DIRECTORY_MASK: u16 = 0x00e0;

#[derive(Debug, Clone)]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct MainHeader {
    pub head_crc: u16,
    pub flags: u16,
    pub head_size: u16,
    pub reserved1: u16,
    pub reserved2: u32,
    pub encrypt_version: Option<u8>,
}

impl MainHeader {
    pub fn has_archive_comment(&self) -> bool {
        self.flags & MHD_COMMENT != 0
    }

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
#[non_exhaustive]
pub enum Block {
    File(FileHeader),
    Comment(CommentHeader),
    NewSub(NewSubHeader),
    End(BlockHeader),
    Unknown(BlockHeader),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlockHeader {
    pub head_crc: u16,
    pub head_type: u8,
    pub flags: u16,
    pub head_size: u16,
    pub add_size: Option<u64>,
    pub offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    pub file_comment: Vec<u8>,
    pub ext_time: Vec<u8>,
    pub packed_range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NewSubHeader {
    pub file: FileHeader,
    pub kind: NewSubKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CommentHeader {
    pub block: BlockHeader,
    pub unp_size: u16,
    pub unp_ver: u8,
    pub method: u8,
    pub comment_crc: u16,
    pub packed_range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NewSubKind {
    ArchiveComment,
    RecoveryRecord,
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterOptions {
    pub target: ArchiveVersion,
    pub features: FeatureSet,
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            target: ArchiveVersion::Rar15,
            features: FeatureSet::store_only(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub file_time: u32,
    pub file_attr: u32,
    pub host_os: u8,
    pub password: Option<&'a [u8]>,
    pub file_comment: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub file_time: u32,
    pub file_attr: u32,
    pub host_os: u8,
    pub password: Option<&'a [u8]>,
    pub file_comment: Option<&'a [u8]>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedEntryMeta {
    pub name: Vec<u8>,
    pub file_time: u32,
    pub attr: u32,
    pub host_os: u8,
    pub is_directory: bool,
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

    pub fn has_file_comment(&self) -> bool {
        self.block.flags & FHD_COMMENT != 0 && !self.file_comment.is_empty()
    }

    pub fn file_comment(&self) -> Result<Option<Vec<u8>>> {
        if !self.has_file_comment() {
            return Ok(None);
        }
        let size = read_u16(&self.file_comment, 0)? as usize;
        let start = 2usize;
        let end = start
            .checked_add(size)
            .ok_or(Error::InvalidHeader("RAR 1.5 file comment size overflows"))?;
        let comment = self.file_comment.get(start..end).ok_or(Error::TooShort)?;
        Ok(Some(comment.to_vec()))
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
        self.stored_data_with_password(archive, None)
    }

    pub fn stored_data_with_password(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if !self.is_stored() {
            return Err(Error::InvalidHeader(
                "RAR 1.5 compressed file extraction is not implemented",
            ));
        }
        if !self.is_encrypted() && self.pack_size != self.unp_size {
            return Err(Error::InvalidHeader(
                "RAR 1.5 stored file has mismatched packed and unpacked sizes",
            ));
        }
        let mut data = self.packed_data_for_decode(archive, password)?;
        if self.is_encrypted() {
            data.truncate(
                usize::try_from(self.unp_size)
                    .map_err(|_| Error::InvalidHeader("RAR 1.5 unpacked size overflows usize"))?,
            );
        }
        Ok(data)
    }

    pub fn unpacked_data(&self, archive: &Archive) -> Result<Vec<u8>> {
        if self.is_stored() {
            return self.stored_data(archive);
        }
        let mut session = DecoderSession::new(false);
        session.decode_file_data(archive, self)
    }

    pub fn unpacked_data_with_password(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if self.is_stored() {
            return self.stored_data_with_password(archive, password);
        }
        let mut session = DecoderSession::new_with_password(false, password);
        session.decode_file_data(archive, self)
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

    pub fn unpacked_data_with_unpack15(
        &self,
        archive: &Archive,
        decoder: &mut Unpack15,
        solid: bool,
    ) -> Result<Vec<u8>> {
        if self.is_stored() {
            return self.stored_data(archive);
        }
        if self.is_encrypted() {
            return Err(Error::InvalidHeader(
                "RAR 1.5 encrypted file extraction is not implemented",
            ));
        }
        if self.unp_ver != 15 {
            return Err(Error::InvalidHeader(
                "RAR 1.5 compressed file extraction is not implemented",
            ));
        }
        decoder
            .decode_member(
                &self.packed_data(archive)?,
                usize::try_from(self.unp_size)
                    .map_err(|_| Error::InvalidHeader("RAR 1.5 unpacked size overflows usize"))?,
                solid,
            )
            .map_err(Into::into)
    }

    pub fn unpacked_data_with_unpack20(
        &self,
        archive: &Archive,
        decoder: &mut Unpack20,
        password: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if self.is_stored() {
            return self.stored_data_with_password(archive, password);
        }
        if self.unp_ver != 20 && self.unp_ver != 26 {
            return Err(Error::InvalidHeader(
                "RAR 2.0 compressed file extraction is not implemented",
            ));
        }
        decoder
            .decode_member(
                &self.packed_data_for_decode(archive, password)?,
                usize::try_from(self.unp_size)
                    .map_err(|_| Error::InvalidHeader("RAR 2.0 unpacked size overflows usize"))?,
            )
            .map_err(Into::into)
    }

    fn packed_data_for_decode(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let mut data = self.packed_data(archive)?;
        self.decrypt_packed_data(&mut data, password)?;
        Ok(data)
    }

    fn decrypt_packed_data(&self, data: &mut [u8], password: Option<&[u8]>) -> Result<()> {
        if !self.is_encrypted() {
            return Ok(());
        }
        let Some(password) = password else {
            return Err(Error::NeedPassword);
        };
        if self.unp_ver == 20 || self.unp_ver == 26 {
            Rar20Cipher::new(password).decrypt_in_place(data);
            return Ok(());
        }
        if self.unp_ver == 15 {
            Rar15Cipher::new(password).crypt_in_place(data);
            return Ok(());
        }
        if self.unp_ver >= 29 {
            Rar30Cipher::new(password, self.salt).decrypt_in_place(data);
            return Ok(());
        }
        Err(Error::InvalidHeader(
            "RAR 1.5 encrypted file extraction is not implemented",
        ))
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

    pub fn metadata(&self) -> ExtractedEntryMeta {
        ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.file_time,
            attr: self.attr,
            host_os: self.host_os,
            is_directory: self.is_directory(),
        }
    }

    pub fn extract_stored(&self, archive: &Archive) -> Result<ExtractedEntry> {
        self.extract_stored_with_password(archive, None)
    }

    pub fn extract_stored_with_password(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
    ) -> Result<ExtractedEntry> {
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

        let data = self.stored_data_with_password(archive, password)?;
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
        self.extract_with_password(archive, None)
    }

    pub fn extract_with_password(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
    ) -> Result<ExtractedEntry> {
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

        let data = self
            .unpacked_data_with_password(archive, password)
            .map_err(|error| self.map_encrypted_payload_error(password, error))?;
        self.verify_crc32(&data)
            .map_err(|error| self.map_encrypted_payload_error(password, error))?;
        Ok(ExtractedEntry {
            name: self.name.clone(),
            data,
            file_time: self.file_time,
            attr: self.attr,
            host_os: self.host_os,
            is_directory: false,
        })
    }

    fn write_stored_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        if !self.is_stored() {
            return Err(Error::InvalidHeader(
                "RAR 1.5 compressed file extraction is not implemented",
            ));
        }
        if !self.is_encrypted() && self.pack_size != self.unp_size {
            return Err(Error::InvalidHeader(
                "RAR 1.5 stored file has mismatched packed and unpacked sizes",
            ));
        }
        let data = self
            .stored_data_with_password(archive, password)
            .map_err(|error| self.map_encrypted_payload_error(password, error))?;
        let actual = crc32(&data);
        if actual == self.file_crc {
            out.write_all(&data)?;
            Ok(())
        } else {
            Err(self.map_encrypted_payload_error(
                password,
                Error::Crc32Mismatch {
                    expected: self.file_crc,
                    actual,
                },
            ))
        }
    }

    fn map_encrypted_payload_error(&self, password: Option<&[u8]>, error: Error) -> Error {
        if !self.is_encrypted() || password.is_none() {
            return error;
        }
        match error {
            Error::NeedPassword => Error::NeedPassword,
            Error::InvalidHeader(message) if message.contains("not implemented") => {
                Error::InvalidHeader(message)
            }
            Error::UnsupportedSignature
            | Error::UnsupportedVersion(_)
            | Error::UnsupportedFeature { .. }
            | Error::TooShort
            | Error::Io(_)
            | Error::AtArchiveOffset { .. }
            | Error::AtEntry { .. } => error,
            Error::InvalidHeader(_)
            | Error::CrcMismatch { .. }
            | Error::Crc32Mismatch { .. }
            | Error::HashMismatch { .. }
            | Error::WrongPasswordOrCorruptData => Error::WrongPasswordOrCorruptData,
        }
    }

    fn entry_error(&self, operation: &'static str, error: Error) -> Error {
        if matches!(
            error,
            Error::NeedPassword | Error::WrongPasswordOrCorruptData
        ) {
            return error;
        }
        error.at_entry(self.name.clone(), operation)
    }

    fn crc_result(&self, actual: u32, password: Option<&[u8]>) -> Result<()> {
        if actual == self.file_crc {
            Ok(())
        } else {
            Err(self.map_encrypted_payload_error(
                password,
                Error::Crc32Mismatch {
                    expected: self.file_crc,
                    actual,
                },
            ))
        }
    }

    fn write_rar29_to(
        &self,
        archive: &Archive,
        decoder: &mut Unpack29,
        out: &mut impl Write,
    ) -> Result<()> {
        if self.is_stored() {
            return self.write_stored_to(archive, None, out);
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

        let mut packed = archive.range_reader(self.packed_range.clone())?;
        let mut crc = Crc32::new();
        let mut crc_writer = CrcWriter {
            inner: out,
            crc: &mut crc,
        };
        decoder
            .decode_member_from_reader(
                &mut packed,
                usize::try_from(self.unp_size)
                    .map_err(|_| Error::InvalidHeader("RAR 1.5 unpacked size overflows usize"))?,
                &mut crc_writer,
            )
            .map_err(Error::from)?;
        let actual = crc.finish();
        if actual == self.file_crc {
            Ok(())
        } else {
            Err(Error::Crc32Mismatch {
                expected: self.file_crc,
                actual,
            })
        }
    }

    fn write_unpack15_to(
        &self,
        archive: &Archive,
        decoder: &mut Unpack15,
        solid: bool,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        if self.is_stored() {
            return self.write_stored_to(archive, password, out);
        }
        if self.unp_ver != 15 {
            return Err(Error::InvalidHeader(
                "RAR 1.5 compressed file extraction is not implemented",
            ));
        }

        if self.is_encrypted() {
            let decrypted = self.packed_data_for_decode(archive, password)?;
            let mut input = Cursor::new(decrypted.as_slice());
            return self
                .write_unpack15_decoded(decoder, solid, &mut input, out, password)
                .map_err(|error| self.map_encrypted_payload_error(password, error));
        }

        let mut input = archive.range_reader(self.packed_range.clone())?;
        self.write_unpack15_decoded(decoder, solid, &mut input, out, password)
    }

    fn write_unpack15_decoded(
        &self,
        decoder: &mut Unpack15,
        solid: bool,
        input: &mut impl Read,
        out: &mut impl Write,
        password: Option<&[u8]>,
    ) -> Result<()> {
        let mut crc = Crc32::new();
        let mut crc_writer = CrcWriter {
            inner: out,
            crc: &mut crc,
        };
        decoder
            .decode_member_from_reader(
                input,
                usize::try_from(self.unp_size)
                    .map_err(|_| Error::InvalidHeader("RAR 1.5 unpacked size overflows usize"))?,
                solid,
                &mut crc_writer,
            )
            .map_err(Error::from)?;
        let actual = crc.finish();
        self.crc_result(actual, password)
    }

    fn write_unpack20_to(
        &self,
        archive: &Archive,
        decoder: &mut Unpack20,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        if self.is_stored() {
            return self.write_stored_to(archive, password, out);
        }
        if self.unp_ver != 20 && self.unp_ver != 26 {
            return Err(Error::InvalidHeader(
                "RAR 2.0 compressed file extraction is not implemented",
            ));
        }

        let mut crc = Crc32::new();
        let mut crc_writer = CrcWriter {
            inner: out,
            crc: &mut crc,
        };
        let target = usize::try_from(self.unp_size)
            .map_err(|_| Error::InvalidHeader("RAR 2.0 unpacked size overflows usize"))?;
        if self.is_encrypted() {
            let data = decoder
                .decode_member(&self.packed_data_for_decode(archive, password)?, target)
                .map_err(Error::from)
                .map_err(|error| self.map_encrypted_payload_error(password, error))?;
            crc_writer.write_all(&data)?;
        } else {
            let mut packed = archive.range_reader(self.packed_range.clone())?;
            decoder
                .decode_member_from_reader(&mut packed, target, &mut crc_writer)
                .map_err(Error::from)?;
        }
        let actual = crc.finish();
        self.crc_result(actual, password)
    }
}

impl NewSubHeader {
    pub fn name_lossy(&self) -> String {
        self.file.name_lossy()
    }
}

impl CommentHeader {
    pub fn packed_data(&self, archive: &Archive) -> Result<Vec<u8>> {
        archive.read_range(self.packed_range.clone())
    }

    pub fn unpacked_data(&self, archive: &Archive) -> Result<Vec<u8>> {
        let target = usize::from(self.unp_size);
        let data = if self.method == 0x30 {
            let data = self.packed_data(archive)?;
            if data.len() != target {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 stored comment has mismatched packed and unpacked sizes",
                ));
            }
            data
        } else if self.unp_ver == 15 {
            Unpack15::default().decode_member(&self.packed_data(archive)?, target, false)?
        } else {
            return Err(Error::InvalidHeader(
                "RAR 1.5 comment compression method is not implemented",
            ));
        };
        let actual = (crc32(&data) & 0xffff) as u16;
        if actual == self.comment_crc {
            Ok(data)
        } else {
            Err(Error::CrcMismatch {
                expected: self.comment_crc,
                actual,
            })
        }
    }
}

impl Archive {
    pub fn parse(input: &[u8]) -> Result<Self> {
        Self::parse_with_password(input, None)
    }

    pub fn parse_with_password(input: &[u8], password: Option<&[u8]>) -> Result<Self> {
        let data: Arc<[u8]> = Arc::from(input.to_vec().into_boxed_slice());
        Self::parse_shared(data, password)
    }

    pub fn parse_path(path: impl AsRef<Path>) -> Result<Self> {
        Self::parse_path_with_password(path, None)
    }

    pub fn parse_path_with_password(
        path: impl AsRef<Path>,
        password: Option<&[u8]>,
    ) -> Result<Self> {
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
        Self::parse_seekable(file, len, sig.offset, ArchiveSource::File(path), password)
    }

    fn parse_shared(input: Arc<[u8]>, password: Option<&[u8]>) -> Result<Self> {
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
            let (block, header, total) = if main.has_encrypted_headers() {
                let password = password.ok_or(Error::NeedPassword)?;
                let encrypted = decrypt_encrypted_header_at(archive, pos, password)?;
                (encrypted.block, encrypted.header, encrypted.total_size)
            } else {
                let block = parse_block_header(archive, pos)?;
                let total = block_total_size(&block)?;
                let header = archive[pos..pos + block.head_size as usize].to_vec();
                (block, header, total)
            };
            match block.head_type {
                FILE_HEAD => {
                    let mut file = parse_file_like_header(&header, relative_block(&block), 0)?;
                    let total = file_block_total_size(&block, total, file.pack_size)?;
                    let next = checked_block_next(&block, total, archive.len())?;
                    file.block.offset = block.offset;
                    file.packed_range =
                        packed_range(sig.offset, block.offset, total, file.pack_size)?;
                    blocks.push(Block::File(file));
                    pos = next;
                }
                NEWSUB_HEAD => {
                    let mut file = parse_file_like_header(&header, relative_block(&block), 0)?;
                    let total = file_block_total_size(&block, total, file.pack_size)?;
                    let next = checked_block_next(&block, total, archive.len())?;
                    file.block.offset = block.offset;
                    file.packed_range =
                        packed_range(sig.offset, block.offset, total, file.pack_size)?;
                    let kind = classify_new_sub(&file.name);
                    blocks.push(Block::NewSub(NewSubHeader { file, kind }));
                    pos = next;
                }
                COMM_HEAD => {
                    let next = checked_block_next(&block, total, archive.len())?;
                    let mut comment = parse_comment_header(&header, relative_block(&block))?;
                    comment.block.offset = block.offset;
                    comment.packed_range =
                        sig.offset + block.offset + 13..sig.offset + block.offset + total;
                    blocks.push(Block::Comment(comment));
                    pos = next;
                }
                ENDARC_HEAD => {
                    let _next = checked_block_next(&block, total, archive.len())?;
                    blocks.push(Block::End(block));
                    break;
                }
                _ => {
                    let next = checked_block_next(&block, total, archive.len())?;
                    blocks.push(Block::Unknown(block));
                    pos = next;
                }
            }
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
        password: Option<&[u8]>,
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
            let (block, header, total) = if main.has_encrypted_headers() {
                let password = password.ok_or(Error::NeedPassword)?;
                let encrypted =
                    read_encrypted_header_at(&mut file, file_len, sfx_offset, pos, password)?;
                (encrypted.block, encrypted.header, encrypted.total_size)
            } else {
                let block = read_block_header_at(&mut file, file_len, sfx_offset, pos)?;
                let total = block_total_size(&block)?;
                let header = read_exact_at(&mut file, sfx_offset + pos, block.head_size as usize)?;
                (block, header, total)
            };
            match block.head_type {
                FILE_HEAD => {
                    let mut file_header =
                        parse_file_like_header(&header, relative_block(&block), 0)?;
                    let total = file_block_total_size(&block, total, file_header.pack_size)?;
                    let next = checked_file_block_next(sfx_offset, &block, total, file_len)?;
                    file_header.block.offset = block.offset;
                    file_header.packed_range =
                        packed_range(sfx_offset, block.offset, total, file_header.pack_size)?;
                    blocks.push(Block::File(file_header));
                    pos = next;
                }
                NEWSUB_HEAD => {
                    let mut file_header =
                        parse_file_like_header(&header, relative_block(&block), 0)?;
                    let total = file_block_total_size(&block, total, file_header.pack_size)?;
                    let next = checked_file_block_next(sfx_offset, &block, total, file_len)?;
                    file_header.block.offset = block.offset;
                    file_header.packed_range =
                        packed_range(sfx_offset, block.offset, total, file_header.pack_size)?;
                    let kind = classify_new_sub(&file_header.name);
                    blocks.push(Block::NewSub(NewSubHeader {
                        file: file_header,
                        kind,
                    }));
                    pos = next;
                }
                COMM_HEAD => {
                    let next = checked_file_block_next(sfx_offset, &block, total, file_len)?;
                    let mut comment = parse_comment_header(&header, relative_block(&block))?;
                    comment.block.offset = block.offset;
                    comment.packed_range =
                        sfx_offset + block.offset + 13..sfx_offset + block.offset + total;
                    blocks.push(Block::Comment(comment));
                    pos = next;
                }
                ENDARC_HEAD => {
                    let _next = checked_file_block_next(sfx_offset, &block, total, file_len)?;
                    blocks.push(Block::End(block));
                    break;
                }
                _ => {
                    let next = checked_file_block_next(sfx_offset, &block, total, file_len)?;
                    blocks.push(Block::Unknown(block));
                    pos = next;
                }
            }
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

    fn range_reader(&self, range: Range<usize>) -> Result<Box<dyn Read + '_>> {
        match &self.source {
            ArchiveSource::Memory(data) => {
                let data = data.get(range).ok_or(Error::TooShort)?;
                Ok(Box::new(Cursor::new(data)))
            }
            ArchiveSource::File(path) => {
                let mut file = File::open(path.as_ref())?;
                file.seek(SeekFrom::Start(range.start as u64))?;
                Ok(Box::new(file.take(range.len() as u64)))
            }
        }
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

    /// Convenience extraction API that buffers each extracted entry in memory.
    ///
    /// Prefer [`Archive::extract_to`] for large archives.
    pub fn extract(&self) -> Result<Vec<ExtractedEntry>> {
        self.extract_with_password(None)
    }

    pub fn extract_with_password(&self, password: Option<&[u8]>) -> Result<Vec<ExtractedEntry>> {
        let mut out = Vec::new();
        let mut session = DecoderSession::new_with_password(self.main.is_solid(), password);
        for file in self.files() {
            if file.is_split_before() || file.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 split entry requires multivolume extraction",
                ));
            }
            out.push(session.extract_file(self, file)?);
        }
        Ok(out)
    }

    /// Streams extracted entries to caller-provided writers.
    pub fn extract_to<F>(&self, open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        self.extract_to_with_password(None, open)
    }

    pub fn extract_to_with_password<F>(&self, password: Option<&[u8]>, mut open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        let mut session = DecoderSession::new_with_password(self.main.is_solid(), password);
        for file in self.files() {
            if file.is_split_before() || file.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 split entry requires multivolume extraction",
                ));
            }
            let meta = file.metadata();
            if meta.is_directory {
                let _ = open(&meta)?;
                continue;
            }
            let mut writer = open(&meta)?;
            if file.is_stored() {
                file.write_stored_to(self, password, &mut writer)
                    .map_err(|error| file.entry_error("extracting", error))?;
            } else {
                session
                    .write_file_to(self, file, &mut writer)
                    .map_err(|error| file.entry_error("extracting", error))?;
            }
        }
        Ok(())
    }

    pub fn archive_comment(&self) -> Result<Option<Vec<u8>>> {
        if let Some(comment) = self.blocks.iter().find_map(|block| match block {
            Block::Comment(comment) => Some(comment),
            _ => None,
        }) {
            return comment.unpacked_data(self).map(Some);
        }

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

    let mut out = Vec::new();
    out.extend_from_slice(RAR15_SIGNATURE);
    write_main_header(
        &mut out,
        if archive_comment.is_some() {
            MHD_COMMENT
        } else {
            0
        },
    );
    write_comment_header(&mut out, archive_comment)?;
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

    let mut out = Vec::new();
    out.extend_from_slice(RAR15_SIGNATURE);
    let mut main_flags = if options.features.solid { MHD_SOLID } else { 0 };
    if archive_comment.is_some() {
        main_flags |= MHD_COMMENT;
    }
    write_main_header(&mut out, main_flags);
    write_comment_header(&mut out, archive_comment)?;
    let mut solid_encoder = options.features.solid.then(Unpack15Encoder::new);
    for (index, entry) in entries.iter().enumerate() {
        let packed = if let Some(encoder) = solid_encoder.as_mut() {
            encoder.encode_member(entry.data)?
        } else {
            unpack15_encode(entry.data)?
        };
        write_compressed_entry(&mut out, entry, &packed, options.target, index != 0)?;
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

    let packed = unpack15_encode(entry.data)?;
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
    if options.target != ArchiveVersion::Rar15 {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = FeatureSet::store_only();
    allowed.file_encryption = options.features.file_encryption;
    allowed.archive_comment = has_archive_comment;
    allowed.file_comment = has_file_comment;
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
    if options.target != ArchiveVersion::Rar15 {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = FeatureSet::store_only();
    allowed.solid = options.features.solid;
    allowed.file_encryption = options.features.file_encryption;
    allowed.archive_comment = has_archive_comment;
    allowed.file_comment = has_file_comment;
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 1.5 writer feature",
        });
    }
    Ok(())
}

fn validate_volume_writer_inputs(
    name: &[u8],
    data: &[u8],
    _password: Option<&[u8]>,
    file_comment: Option<&[u8]>,
    options: WriterOptions,
) -> Result<()> {
    validate_file_entry(name, data)?;
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
    data: &mut [u8],
    target: ArchiveVersion,
    password: &[u8],
) -> Result<()> {
    match target {
        ArchiveVersion::Rar15 => {
            Rar15Cipher::new(password).crypt_in_place(data);
            Ok(())
        }
        _ => Err(Error::UnsupportedVersion(target)),
    }
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

fn write_stored_entry(
    out: &mut Vec<u8>,
    entry: &StoredEntry<'_>,
    target: ArchiveVersion,
) -> Result<()> {
    validate_stored_entry(entry)?;
    let mut packed = entry.data.to_vec();
    if let Some(password) = entry.password {
        Rar15Cipher::new(password).crypt_in_place(&mut packed);
    }
    let file_comment = encode_file_comment(entry.file_comment)?;
    write_file_header_and_data(
        out,
        FileRecord {
            name: entry.name,
            unpacked_size: entry.data.len(),
            file_crc: crc32(entry.data),
            packed: &packed,
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            target,
            method: 0x30,
            flags: writer_file_flags(entry.password, entry.file_comment, false),
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
    let mut packed = packed.to_vec();
    if let Some(password) = entry.password {
        Rar15Cipher::new(password).crypt_in_place(&mut packed);
    }
    let file_comment = encode_file_comment(entry.file_comment)?;
    write_file_header_and_data(
        out,
        FileRecord {
            name: entry.name,
            unpacked_size: entry.data.len(),
            file_crc: crc32(entry.data),
            packed: &packed,
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            target,
            method: 0x33,
            flags: writer_file_flags(entry.password, entry.file_comment, solid_continuation),
            extra: &file_comment,
        },
    )
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
    extra: &'a [u8],
}

fn write_file_header_and_data(out: &mut Vec<u8>, record: FileRecord<'_>) -> Result<()> {
    let start = out.len();
    let packed_size = u32::try_from(record.packed.len())
        .map_err(|_| Error::InvalidHeader("RAR 1.5 packed size overflows u32"))?;
    let unpacked_size = u32::try_from(record.unpacked_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 unpacked size overflows u32"))?;
    let head_size = 32usize
        .checked_add(record.name.len())
        .and_then(|size| size.checked_add(record.extra.len()))
        .ok_or(Error::InvalidHeader("RAR 1.5 file header size overflows"))?;
    let head_size = u16::try_from(head_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 file header size overflows"))?;
    let unp_ver = match record.target {
        ArchiveVersion::Rar15 => 15,
        _ => return Err(Error::UnsupportedVersion(record.target)),
    };

    out.extend_from_slice(&0u16.to_le_bytes());
    out.push(FILE_HEAD);
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
    out.extend_from_slice(record.extra);
    write_file_header_crc(out, start, record.name.len(), record.flags);
    out.extend_from_slice(record.packed);
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
    if let Some(password) = entry.password {
        encrypt_split_packed_data(&mut packed, entry.target, password)?;
    }

    let chunks: Vec<&[u8]> = packed.chunks(entry.max_packed_per_volume).collect();
    if chunks.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume writer needs at least two volumes",
        ));
    }

    let mut volumes = Vec::with_capacity(chunks.len());
    let file_crc = crc32(entry.unpacked);
    for (index, chunk) in chunks.iter().enumerate() {
        let split_before = index > 0;
        let split_after = index + 1 < chunks.len();
        let mut file_flags = entry.base_flags;
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
                name: entry.name,
                unpacked_size: entry.unpacked.len(),
                file_crc,
                packed: chunk,
                file_time: entry.file_time,
                file_attr: entry.file_attr,
                host_os: entry.host_os,
                target: entry.target,
                method: entry.method,
                flags: file_flags,
                extra: &[],
            },
        )?;
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

fn parse_comment_header(input: &[u8], block: BlockHeader) -> Result<CommentHeader> {
    if block.head_size < 13 {
        return Err(Error::InvalidHeader("RAR 1.5 comment header is too short"));
    }
    let start = block.offset;
    Ok(CommentHeader {
        block,
        unp_size: read_u16(input, start + 7)?,
        unp_ver: *input.get(start + 9).ok_or(Error::TooShort)?,
        method: *input.get(start + 10).ok_or(Error::TooShort)?,
        comment_crc: read_u16(input, start + 11)?,
        packed_range: 0..0,
    })
}

struct EncryptedHeader {
    block: BlockHeader,
    header: Vec<u8>,
    total_size: usize,
}

fn decrypt_encrypted_header_at(
    archive: &[u8],
    offset: usize,
    password: &[u8],
) -> Result<EncryptedHeader> {
    let salt = read_header_salt(archive, offset)?;
    let first_ciphertext = archive
        .get(offset + 8..offset + 24)
        .ok_or(Error::TooShort)?;
    let mut cipher = Rar30Cipher::new(password, Some(salt));
    let mut first_block: [u8; 16] = first_ciphertext
        .try_into()
        .expect("RAR encrypted header first block size");
    cipher.decrypt_block(&mut first_block);
    let head_size = read_u16(&first_block, 5)? as usize;
    if head_size < 7 {
        return Err(Error::InvalidHeader("RAR 1.5 block header is too short"));
    }
    let encrypted_header_size = align16(head_size)?;
    let encrypted_start = offset
        .checked_add(8)
        .ok_or(Error::InvalidHeader("RAR 1.5 block offset overflows usize"))?;
    let encrypted_end = encrypted_start
        .checked_add(encrypted_header_size)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let encrypted = archive
        .get(encrypted_start..encrypted_end)
        .ok_or(Error::TooShort)?;
    let mut header = encrypted.to_vec();
    let mut cipher = Rar30Cipher::new(password, Some(salt));
    cipher.decrypt_in_place(&mut header);
    header.truncate(head_size);

    let mut block = parse_block_header(&header, 0)?;
    block.offset = offset;
    let payload_size = usize::try_from(block.add_size.unwrap_or(0))
        .map_err(|_| Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let total_size = 8usize
        .checked_add(encrypted_header_size)
        .and_then(|size| size.checked_add(payload_size))
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    Ok(EncryptedHeader {
        block,
        header,
        total_size,
    })
}

fn read_encrypted_header_at(
    file: &mut File,
    file_len: u64,
    archive_offset: usize,
    offset: usize,
    password: &[u8],
) -> Result<EncryptedHeader> {
    let absolute = archive_offset
        .checked_add(offset)
        .ok_or(Error::InvalidHeader("RAR 1.5 block offset overflows usize"))?;
    if absolute as u64 + 24 > file_len {
        return Err(Error::TooShort);
    }
    let first = read_exact_at(file, absolute, 24)?;
    let salt = read_header_salt(&first, 0)?;
    let mut cipher = Rar30Cipher::new(password, Some(salt));
    let mut first_block: [u8; 16] = first[8..24]
        .try_into()
        .expect("RAR encrypted header first block size");
    cipher.decrypt_block(&mut first_block);
    let head_size = read_u16(&first_block, 5)? as usize;
    if head_size < 7 {
        return Err(Error::InvalidHeader("RAR 1.5 block header is too short"));
    }
    let encrypted_header_size = align16(head_size)?;
    let encrypted_start = absolute
        .checked_add(8)
        .ok_or(Error::InvalidHeader("RAR 1.5 block offset overflows usize"))?;
    if encrypted_start as u64 + encrypted_header_size as u64 > file_len {
        return Err(Error::TooShort);
    }
    let mut header = read_exact_at(file, encrypted_start, encrypted_header_size)?;
    let mut cipher = Rar30Cipher::new(password, Some(salt));
    cipher.decrypt_in_place(&mut header);
    header.truncate(head_size);

    let mut block = parse_block_header(&header, 0)?;
    block.offset = offset;
    let payload_size = usize::try_from(block.add_size.unwrap_or(0))
        .map_err(|_| Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let total_size = 8usize
        .checked_add(encrypted_header_size)
        .and_then(|size| size.checked_add(payload_size))
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    Ok(EncryptedHeader {
        block,
        header,
        total_size,
    })
}

fn read_header_salt(input: &[u8], offset: usize) -> Result<[u8; 8]> {
    input
        .get(offset..offset + 8)
        .ok_or(Error::TooShort)
        .map(|salt| salt.try_into().expect("RAR 3 salt size"))
}

fn align16(size: usize) -> Result<usize> {
    size.checked_add(15)
        .map(|size| size & !15)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))
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
    let name = decode_file_name(&input[pos..name_end], block.flags);
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

    let file_comment = if block.flags & FHD_COMMENT != 0 {
        if pos + 2 <= head_end {
            let comment_len = read_u16(input, pos)? as usize;
            let comment_total = comment_len
                .checked_add(2)
                .ok_or(Error::InvalidHeader("RAR 1.5 file comment size overflows"))?;
            let comment_end = pos
                .checked_add(comment_total)
                .ok_or(Error::InvalidHeader("RAR 1.5 file comment size overflows"))?;
            if comment_end <= head_end {
                let comment = input[pos..comment_end].to_vec();
                pos = comment_end;
                comment
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
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
        file_comment,
        ext_time,
        packed_range: archive_offset + data_start..archive_offset + data_end,
    })
}

fn decode_file_name(raw: &[u8], flags: u16) -> Vec<u8> {
    if flags & FHD_UNICODE == 0 {
        return raw.to_vec();
    }

    let Some(zero_pos) = raw.iter().position(|byte| *byte == 0) else {
        return raw.to_vec();
    };
    if zero_pos + 1 >= raw.len() {
        return raw[..zero_pos].to_vec();
    }

    let fallback = &raw[..zero_pos];
    let high_byte = raw[zero_pos + 1];
    let encoded = &raw[zero_pos + 2..];
    let mut pos = 0usize;
    let mut flag_byte = 0u8;
    let mut flag_bits = 0u8;
    let mut dst_pos = 0usize;
    let mut units = Vec::new();

    while pos < encoded.len() {
        if flag_bits == 0 {
            flag_byte = encoded[pos];
            pos += 1;
            flag_bits = 8;
        }
        let mode = flag_byte >> 6;
        flag_byte <<= 2;
        flag_bits -= 2;

        match mode {
            0 => {
                let Some(&low) = encoded.get(pos) else {
                    return raw.to_vec();
                };
                pos += 1;
                units.push(u16::from(low));
                dst_pos += 1;
            }
            1 => {
                let Some(&low) = encoded.get(pos) else {
                    return raw.to_vec();
                };
                pos += 1;
                units.push((u16::from(high_byte) << 8) | u16::from(low));
                dst_pos += 1;
            }
            2 => {
                let Some((&low, &high)) = encoded.get(pos).zip(encoded.get(pos + 1)) else {
                    return raw.to_vec();
                };
                pos += 2;
                units.push((u16::from(high) << 8) | u16::from(low));
                dst_pos += 1;
            }
            3 => {
                let Some(&length_byte) = encoded.get(pos) else {
                    return raw.to_vec();
                };
                pos += 1;
                let (count, correction, high) = if length_byte & 0x80 != 0 {
                    let Some(&correction) = encoded.get(pos) else {
                        return raw.to_vec();
                    };
                    pos += 1;
                    ((length_byte & 0x7f) as usize + 2, correction, high_byte)
                } else {
                    (length_byte as usize + 2, 0, 0)
                };
                for _ in 0..count {
                    let low = fallback
                        .get(dst_pos)
                        .copied()
                        .unwrap_or(b'?')
                        .wrapping_add(correction);
                    units.push((u16::from(high) << 8) | u16::from(low));
                    dst_pos += 1;
                }
            }
            _ => unreachable!("2-bit filename mode"),
        }
    }

    char::decode_utf16(units)
        .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect::<String>()
        .into_bytes()
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

struct CrcWriter<'a, W: Write + ?Sized> {
    inner: &'a mut W,
    crc: &'a mut Crc32,
}

impl<W: Write + ?Sized> Write for CrcWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.crc.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct Crc32 {
    value: u32,
}

impl Crc32 {
    fn new() -> Self {
        Self { value: 0xffff_ffff }
    }

    fn update(&mut self, input: &[u8]) {
        for &byte in input {
            self.value ^= byte as u32;
            for _ in 0..8 {
                let mask = 0u32.wrapping_sub(self.value & 1);
                self.value = (self.value >> 1) ^ (0xedb8_8320 & mask);
            }
        }
    }

    fn finish(self) -> u32 {
        !self.value
    }
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
        let header_end = header_crc_end(input, offset, head_type, flags, head_size)?;
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

fn header_crc_end(
    input: &[u8],
    offset: usize,
    head_type: u8,
    flags: u16,
    head_size: u16,
) -> Result<usize> {
    let full_end = offset + head_size as usize;
    let fixed_end = match head_type {
        MAIN_HEAD if flags & MHD_COMMENT != 0 => Some(offset + 13),
        COMM_HEAD => Some(offset + 13),
        FILE_HEAD if flags & FHD_COMMENT != 0 => Some(file_header_comment_crc_end(input, offset)?),
        _ => None,
    };
    Ok(fixed_end.unwrap_or(full_end).min(full_end))
}

fn file_header_comment_crc_end(input: &[u8], offset: usize) -> Result<usize> {
    if input.len() < offset + 32 {
        return Err(Error::TooShort);
    }
    let flags = read_u16(input, offset + 3)?;
    let name_size = read_u16(input, offset + 26)? as usize;
    let mut end = offset + 32;
    if flags & FHD_LARGE != 0 {
        end = end
            .checked_add(8)
            .ok_or(Error::InvalidHeader("RAR 1.5 file header size overflows"))?;
    }
    end = end
        .checked_add(name_size)
        .ok_or(Error::InvalidHeader("RAR 1.5 file header size overflows"))?;
    if flags & FHD_SALT != 0 {
        end = end
            .checked_add(8)
            .ok_or(Error::InvalidHeader("RAR 1.5 file header size overflows"))?;
    }
    Ok(end)
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

fn file_block_total_size(
    block: &BlockHeader,
    default_total: usize,
    pack_size: u64,
) -> Result<usize> {
    let low_payload_size = usize::try_from(block.add_size.unwrap_or(0))
        .map_err(|_| Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let header_prefix = default_total
        .checked_sub(low_payload_size)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let pack_size = usize::try_from(pack_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 packed file size overflows usize"))?;
    header_prefix
        .checked_add(pack_size)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))
}

fn checked_block_next(block: &BlockHeader, total: usize, archive_len: usize) -> Result<usize> {
    let next = block
        .offset
        .checked_add(total)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    if next > archive_len {
        return Err(Error::TooShort);
    }
    Ok(next)
}

fn checked_file_block_next(
    sfx_offset: usize,
    block: &BlockHeader,
    total: usize,
    file_len: u64,
) -> Result<usize> {
    let next = block
        .offset
        .checked_add(total)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let absolute_next = sfx_offset
        .checked_add(next)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    if absolute_next as u64 > file_len {
        return Err(Error::TooShort);
    }
    Ok(next)
}

fn packed_range(
    archive_offset: usize,
    block_offset: usize,
    total: usize,
    pack_size: u64,
) -> Result<Range<usize>> {
    let pack_size = usize::try_from(pack_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 packed file size overflows usize"))?;
    let block_end = archive_offset
        .checked_add(block_offset)
        .and_then(|start| start.checked_add(total))
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let block_start = block_end
        .checked_sub(pack_size)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    Ok(block_start..block_end)
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
    let mut crc = Crc32::new();
    crc.update(input);
    crc.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fhd_large_high_size_fields_from_file_header() {
        let name = b"large.bin";
        let head_size = 32 + 8 + name.len();
        let mut header = Vec::new();
        header.extend_from_slice(&0u16.to_le_bytes());
        header.push(FILE_HEAD);
        header.extend_from_slice(&(LONG_BLOCK | FHD_LARGE).to_le_bytes());
        header.extend_from_slice(&(head_size as u16).to_le_bytes());
        header.extend_from_slice(&0x89ab_cdefu32.to_le_bytes());
        header.extend_from_slice(&0x7654_3210u32.to_le_bytes());
        header.push(3);
        header.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        header.extend_from_slice(&0x5a21_0000u32.to_le_bytes());
        header.push(29);
        header.push(0x35);
        header.extend_from_slice(&(name.len() as u16).to_le_bytes());
        header.extend_from_slice(&0x20u32.to_le_bytes());
        header.extend_from_slice(&1u32.to_le_bytes());
        header.extend_from_slice(&2u32.to_le_bytes());
        header.extend_from_slice(name);

        let block = BlockHeader {
            head_crc: 0,
            head_type: FILE_HEAD,
            flags: LONG_BLOCK | FHD_LARGE,
            head_size: head_size as u16,
            add_size: Some(0x89ab_cdef),
            offset: 0,
        };
        let file = parse_file_like_header(&header, block, 0).unwrap();

        assert_eq!(file.pack_size, 0x0000_0001_89ab_cdef);
        assert_eq!(file.unp_size, 0x0000_0002_7654_3210);
        assert_eq!(file.name, name);
        assert_eq!(
            file.packed_range,
            head_size..head_size + 0x0000_0001_89ab_cdefusize
        );
    }

    #[test]
    fn fhd_large_archive_extent_uses_high_packed_size_without_underflowing() {
        let name = b"large-zero-low.bin";
        let head_size = 32 + 8 + name.len();
        let mut archive = Vec::from(RAR15_SIGNATURE);
        write_main_header(&mut archive, 0);

        let start = archive.len();
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.push(FILE_HEAD);
        archive.extend_from_slice(&(LONG_BLOCK | FHD_LARGE).to_le_bytes());
        archive.extend_from_slice(&(head_size as u16).to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.push(3);
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&0x5a21_0000u32.to_le_bytes());
        archive.push(29);
        archive.push(0x35);
        archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
        archive.extend_from_slice(&0x20u32.to_le_bytes());
        archive.extend_from_slice(&1u32.to_le_bytes());
        archive.extend_from_slice(&1u32.to_le_bytes());
        archive.extend_from_slice(name);
        write_header_crc(&mut archive, start);

        assert!(matches!(Archive::parse(&archive), Err(Error::TooShort)));
    }
}
