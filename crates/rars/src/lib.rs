pub use rars_format::{
    detect_archive_family, find_archive_start, rar13, rar15_40, rar50, ArchiveFamily,
    ArchiveReadOptions, ArchiveSignature, ArchiveVersion, Error, FeatureSet, Result,
};
use std::io::{Read, Write};
use std::path::Path;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Archive {
    Rar13(rar13::Archive),
    Rar15To40(rar15_40::Archive),
    Rar50Plus(rar50::Archive),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractedEntry {
    pub name: Vec<u8>,
    pub data: Vec<u8>,
    pub file_time: u32,
    pub file_attr: u32,
    pub is_directory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractedEntryMeta {
    pub name: Vec<u8>,
    pub file_time: u32,
    pub file_attr: u32,
    pub is_directory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArchiveMember {
    pub meta: ArchiveMemberMeta,
    pub detail: ArchiveMemberDetail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArchiveMemberMeta {
    pub family: ArchiveFamily,
    pub name: Vec<u8>,
    pub packed_size: u64,
    pub unpacked_size: u64,
    pub file_time: Option<u32>,
    pub file_attr: u64,
    pub host_os: Option<u64>,
    pub is_directory: bool,
    pub is_encrypted: bool,
    pub is_stored: bool,
    pub is_split_before: bool,
    pub is_split_after: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveMemberDetail {
    #[non_exhaustive]
    Rar13 {
        method: u8,
        unpack_version: u8,
        file_checksum: u16,
        has_file_comment: bool,
    },
    #[non_exhaustive]
    Rar15To40 {
        method: u8,
        unpack_version: u8,
        crc32: u32,
        solid: bool,
        salt: Option<[u8; 8]>,
        has_file_comment: bool,
    },
    #[non_exhaustive]
    Rar50Plus {
        compression_info: u64,
        crc32: Option<u32>,
        hash: Option<ArchiveMemberHash>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveMemberHash {
    Blake2sp([u8; 32]),
    Other { hash_type: u64, data: Vec<u8> },
}

impl Archive {
    pub fn family(&self) -> ArchiveFamily {
        match self {
            Self::Rar13(_) => ArchiveFamily::Rar13,
            Self::Rar15To40(_) => ArchiveFamily::Rar15To40,
            Self::Rar50Plus(_) => ArchiveFamily::Rar50Plus,
        }
    }

    pub fn sfx_offset(&self) -> usize {
        match self {
            Self::Rar13(archive) => archive.sfx_offset,
            Self::Rar15To40(archive) => archive.sfx_offset,
            Self::Rar50Plus(archive) => archive.sfx_offset,
        }
    }

    pub fn members(&self) -> Box<dyn Iterator<Item = ArchiveMember> + '_> {
        match self {
            Self::Rar13(archive) => Box::new(archive.entries.iter().map(rar13_member)),
            Self::Rar15To40(archive) => Box::new(archive.files().map(rar15_40_member)),
            Self::Rar50Plus(archive) => Box::new(archive.files().map(rar50_member)),
        }
    }

    /// Convenience extraction API that buffers each extracted entry in memory.
    ///
    /// Prefer [`Archive::extract_to`] for large archives or normal CLI-style
    /// extraction.
    pub fn extract(&self, password: Option<&[u8]>) -> Result<Vec<ExtractedEntry>> {
        match self {
            Self::Rar13(archive) => archive
                .extract(password)
                .map(|entries| entries.into_iter().map(Into::into).collect()),
            Self::Rar15To40(archive) => archive
                .extract_with_password(password)
                .map(|entries| entries.into_iter().map(Into::into).collect()),
            Self::Rar50Plus(archive) => archive
                .extract_with_password(password)
                .map(|entries| entries.into_iter().map(Into::into).collect()),
        }
    }

    /// Streams extracted entries to caller-provided writers.
    pub fn extract_to<F>(&self, password: Option<&[u8]>, mut open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        match self {
            Self::Rar13(archive) => archive.extract_to(password, |meta| open(&rar13_meta(meta))),
            Self::Rar15To40(archive) => {
                archive.extract_to_with_password(password, |meta| open(&rar15_40_meta(meta)))
            }
            Self::Rar50Plus(archive) => {
                archive.extract_to_with_password(password, |meta| open(&rar50_meta(meta)?))
            }
        }
    }

    pub fn repair_recovery(&self) -> Result<Vec<u8>> {
        match self {
            Self::Rar15To40(archive) => archive.repair_protect_head(),
            Self::Rar50Plus(archive) => archive.repair_inline_recovery(),
            Self::Rar13(_) => Err(Error::UnsupportedFeature {
                version: ArchiveVersion::Rar14,
                feature: "recovery repair for RAR 1.3/1.4 archives",
            }),
        }
    }

    pub fn as_rar13(&self) -> Option<&rar13::Archive> {
        match self {
            Self::Rar13(archive) => Some(archive),
            Self::Rar15To40(_) => None,
            Self::Rar50Plus(_) => None,
        }
    }

    pub fn as_rar15_40(&self) -> Option<&rar15_40::Archive> {
        match self {
            Self::Rar13(_) => None,
            Self::Rar15To40(archive) => Some(archive),
            Self::Rar50Plus(_) => None,
        }
    }

    pub fn as_rar50(&self) -> Option<&rar50::Archive> {
        match self {
            Self::Rar13(_) | Self::Rar15To40(_) => None,
            Self::Rar50Plus(archive) => Some(archive),
        }
    }
}

fn rar13_member(entry: &rar13::Entry) -> ArchiveMember {
    ArchiveMember {
        meta: ArchiveMemberMeta {
            family: ArchiveFamily::Rar13,
            name: entry.name.clone(),
            packed_size: u64::from(entry.header.pack_size),
            unpacked_size: u64::from(entry.header.unp_size),
            file_time: Some(entry.header.file_time),
            file_attr: u64::from(entry.header.file_attr),
            host_os: None,
            is_directory: entry.is_directory(),
            is_encrypted: entry.is_encrypted(),
            is_stored: entry.is_stored(),
            is_split_before: entry.is_split_before(),
            is_split_after: entry.is_split_after(),
        },
        detail: ArchiveMemberDetail::Rar13 {
            method: entry.header.method,
            unpack_version: entry.header.unp_ver,
            file_checksum: entry.header.file_crc,
            has_file_comment: entry.has_file_comment(),
        },
    }
}

fn rar15_40_member(file: &rar15_40::FileHeader) -> ArchiveMember {
    ArchiveMember {
        meta: ArchiveMemberMeta {
            family: ArchiveFamily::Rar15To40,
            name: file.name.clone(),
            packed_size: file.pack_size,
            unpacked_size: file.unp_size,
            file_time: Some(file.file_time),
            file_attr: u64::from(file.attr),
            host_os: Some(u64::from(file.host_os)),
            is_directory: file.is_directory(),
            is_encrypted: file.is_encrypted(),
            is_stored: file.is_stored(),
            is_split_before: file.is_split_before(),
            is_split_after: file.is_split_after(),
        },
        detail: ArchiveMemberDetail::Rar15To40 {
            method: file.method,
            unpack_version: file.unp_ver,
            crc32: file.file_crc,
            solid: file.is_solid(),
            salt: file.salt,
            has_file_comment: file.has_file_comment(),
        },
    }
}

fn rar50_member(file: &rar50::FileHeader) -> ArchiveMember {
    ArchiveMember {
        meta: ArchiveMemberMeta {
            family: ArchiveFamily::Rar50Plus,
            name: file.name.clone(),
            packed_size: file.packed_size(),
            unpacked_size: file.unpacked_size,
            file_time: file.mtime,
            file_attr: file.attributes,
            host_os: Some(file.host_os),
            is_directory: file.is_directory(),
            is_encrypted: file.encrypted,
            is_stored: file.is_stored(),
            is_split_before: file.is_split_before(),
            is_split_after: file.is_split_after(),
        },
        detail: ArchiveMemberDetail::Rar50Plus {
            compression_info: file.compression_info,
            crc32: file.data_crc32,
            hash: file.hash.as_ref().map(rar50_member_hash),
        },
    }
}

fn rar50_member_hash(hash: &rar50::FileHash) -> ArchiveMemberHash {
    match hash.hash_type {
        0 if hash.data.len() == 32 => {
            let mut data = [0; 32];
            data.copy_from_slice(&hash.data);
            ArchiveMemberHash::Blake2sp(data)
        }
        _ => ArchiveMemberHash::Other {
            hash_type: hash.hash_type,
            data: hash.data.clone(),
        },
    }
}

impl From<rar13::ExtractedEntry> for ExtractedEntry {
    fn from(entry: rar13::ExtractedEntry) -> Self {
        Self {
            name: entry.name,
            data: entry.data,
            file_time: entry.file_time,
            file_attr: entry.file_attr as u32,
            is_directory: entry.is_directory,
        }
    }
}

impl From<rar15_40::ExtractedEntry> for ExtractedEntry {
    fn from(entry: rar15_40::ExtractedEntry) -> Self {
        Self {
            name: entry.name,
            data: entry.data,
            file_time: entry.file_time,
            file_attr: entry.attr,
            is_directory: entry.is_directory,
        }
    }
}

impl From<rar50::ExtractedEntry> for ExtractedEntry {
    fn from(entry: rar50::ExtractedEntry) -> Self {
        Self {
            name: entry.name,
            data: entry.data,
            file_time: entry.file_time,
            file_attr: entry.attr as u32,
            is_directory: entry.is_directory,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ArchiveReader;

impl ArchiveReader {
    pub fn detect(input: &[u8]) -> Result<ArchiveSignature> {
        detect_archive_family(input).ok_or(Error::UnsupportedSignature)
    }

    pub fn read(input: &[u8]) -> Result<Archive> {
        Self::read_with_options(input, ArchiveReadOptions::default())
    }

    pub fn read_with_options(input: &[u8], options: ArchiveReadOptions<'_>) -> Result<Archive> {
        let signature = find_archive_start(input, 128 * 1024).ok_or(Error::UnsupportedSignature)?;
        match signature.family {
            ArchiveFamily::Rar13 => Ok(Archive::Rar13(rar13::Archive::parse(input)?)),
            ArchiveFamily::Rar15To40 => Ok(Archive::Rar15To40(
                rar15_40::Archive::parse_with_options(input, options)?,
            )),
            ArchiveFamily::Rar50Plus => Ok(Archive::Rar50Plus(rar50::Archive::parse_with_options(
                input, options,
            )?)),
        }
    }

    pub fn read_path(path: impl AsRef<Path>) -> Result<Archive> {
        Self::read_path_with_options(path, ArchiveReadOptions::default())
    }

    pub fn read_path_with_options(
        path: impl AsRef<Path>,
        options: ArchiveReadOptions<'_>,
    ) -> Result<Archive> {
        let path = path.as_ref();
        let mut file = std::fs::File::open(path)?;
        let len = file.metadata()?.len();
        let mut scan = vec![0; len.min(128 * 1024) as usize];
        file.read_exact(&mut scan)?;
        let signature = find_archive_start(&scan, 128 * 1024).ok_or(Error::UnsupportedSignature)?;
        match signature.family {
            ArchiveFamily::Rar13 => Ok(Archive::Rar13(rar13::Archive::parse_path(path)?)),
            ArchiveFamily::Rar15To40 => Ok(Archive::Rar15To40(
                rar15_40::Archive::parse_path_with_options(path, options)?,
            )),
            ArchiveFamily::Rar50Plus => Ok(Archive::Rar50Plus(
                rar50::Archive::parse_path_with_options(path, options)?,
            )),
        }
    }
}

fn read_options(password: Option<&[u8]>) -> ArchiveReadOptions<'_> {
    match password {
        Some(password) => ArchiveReadOptions::with_password(password),
        None => ArchiveReadOptions::new(),
    }
}

/// Convenience multivolume extraction API that buffers each extracted entry in
/// memory. Prefer [`extract_volumes_to`] for large archives.
pub fn extract_volumes(
    archives: &[Archive],
    password: Option<&[u8]>,
) -> Result<Vec<ExtractedEntry>> {
    let Some(first) = archives.first() else {
        return Err(Error::InvalidHeader("volume set is empty"));
    };

    match first.family() {
        ArchiveFamily::Rar13 => {
            let typed = rar13_volumes(archives)?;
            rar13::extract_volumes(&typed, password)
                .map(|entries| entries.into_iter().map(Into::into).collect())
        }
        ArchiveFamily::Rar15To40 => {
            let typed = rar15_40_volumes(archives)?;
            rar15_40::extract_volumes_with_options(&typed, read_options(password))
                .map(|entries| entries.into_iter().map(Into::into).collect())
        }
        ArchiveFamily::Rar50Plus => {
            let typed = rar50_volumes(archives)?;
            rar50::extract_volumes_with_options(&typed, read_options(password))
                .map(|entries| entries.into_iter().map(Into::into).collect())
        }
    }
}

/// Streams a multivolume archive set to caller-provided writers.
pub fn extract_volumes_to<F>(
    archives: &[Archive],
    password: Option<&[u8]>,
    mut open: F,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    let Some(first) = archives.first() else {
        return Err(Error::InvalidHeader("volume set is empty"));
    };

    match first.family() {
        ArchiveFamily::Rar13 => {
            let typed = rar13_volumes(archives)?;
            rar13::extract_volumes_to(&typed, password, |meta| open(&rar13_meta(meta)))
        }
        ArchiveFamily::Rar15To40 => {
            let typed = rar15_40_volumes(archives)?;
            rar15_40::extract_volumes_to_with_options(&typed, read_options(password), |meta| {
                open(&rar15_40_meta(meta))
            })
        }
        ArchiveFamily::Rar50Plus => {
            let typed = rar50_volumes(archives)?;
            rar50::extract_volumes_to_with_options(&typed, read_options(password), |meta| {
                open(&rar50_meta(meta)?)
            })
        }
    }
}

fn rar13_meta(meta: &rar13::ExtractedEntryMeta) -> ExtractedEntryMeta {
    ExtractedEntryMeta {
        name: meta.name.clone(),
        file_time: meta.file_time,
        file_attr: u32::from(meta.file_attr),
        is_directory: meta.is_directory,
    }
}

fn rar15_40_meta(meta: &rar15_40::ExtractedEntryMeta) -> ExtractedEntryMeta {
    ExtractedEntryMeta {
        name: meta.name.clone(),
        file_time: meta.file_time,
        file_attr: meta.attr,
        is_directory: meta.is_directory,
    }
}

fn rar50_meta(meta: &rar50::ExtractedEntryMeta) -> Result<ExtractedEntryMeta> {
    Ok(ExtractedEntryMeta {
        name: meta.name.clone(),
        file_time: meta.file_time,
        file_attr: u32::try_from(meta.attr)
            .map_err(|_| Error::InvalidHeader("RAR 5 file attributes overflow u32"))?,
        is_directory: meta.is_directory,
    })
}

fn rar13_volumes(archives: &[Archive]) -> Result<Vec<rar13::Archive>> {
    archives
        .iter()
        .map(|archive| match archive {
            Archive::Rar13(archive) => Ok(archive.clone()),
            Archive::Rar15To40(_) | Archive::Rar50Plus(_) => {
                Err(Error::InvalidHeader("mixed archive families in volume set"))
            }
        })
        .collect()
}

fn rar15_40_volumes(archives: &[Archive]) -> Result<Vec<rar15_40::Archive>> {
    archives
        .iter()
        .map(|archive| match archive {
            Archive::Rar15To40(archive) => Ok(archive.clone()),
            Archive::Rar13(_) | Archive::Rar50Plus(_) => {
                Err(Error::InvalidHeader("mixed archive families in volume set"))
            }
        })
        .collect()
}

fn rar50_volumes(archives: &[Archive]) -> Result<Vec<rar50::Archive>> {
    archives
        .iter()
        .map(|archive| match archive {
            Archive::Rar50Plus(archive) => Ok(archive.clone()),
            Archive::Rar13(_) | Archive::Rar15To40(_) => {
                Err(Error::InvalidHeader("mixed archive families in volume set"))
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy)]
pub struct ArchiveWriter {
    target: ArchiveVersion,
    features: FeatureSet,
}

impl ArchiveWriter {
    pub fn new(target: ArchiveVersion) -> Result<Self> {
        match target.family() {
            ArchiveFamily::Rar13 | ArchiveFamily::Rar15To40 | ArchiveFamily::Rar50Plus => {
                Ok(Self {
                    target,
                    features: FeatureSet::store_only(),
                })
            }
        }
    }

    pub fn with_features(mut self, features: FeatureSet) -> Self {
        self.features = features;
        self
    }

    pub fn write_stored(self, entries: &[rar13::StoredEntry<'_>]) -> Result<Vec<u8>> {
        if !self.target.is_rar13_family() {
            return Err(Error::UnsupportedVersion(self.target));
        }
        rar13::write_stored_archive(
            entries,
            rar13::WriterOptions {
                target: self.target,
                features: self.features,
            },
        )
    }

    pub fn write_compressed(self, entries: &[rar13::FileEntry<'_>]) -> Result<Vec<u8>> {
        if !self.target.is_rar13_family() {
            return Err(Error::UnsupportedVersion(self.target));
        }
        rar13::write_compressed_archive(
            entries,
            rar13::WriterOptions {
                target: self.target,
                features: self.features,
            },
        )
    }

    pub fn write_rar15_stored(self, entries: &[rar15_40::StoredEntry<'_>]) -> Result<Vec<u8>> {
        rar15_40::write_stored_archive(
            entries,
            rar15_40::WriterOptions {
                target: self.target,
                features: self.features,
            },
        )
    }

    pub fn write_rar15_stored_with_comment(
        self,
        entries: &[rar15_40::StoredEntry<'_>],
        archive_comment: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        rar15_40::write_stored_archive_with_comment(
            entries,
            rar15_40::WriterOptions {
                target: self.target,
                features: self.features,
            },
            archive_comment,
        )
    }

    pub fn write_rar15_compressed(self, entries: &[rar15_40::FileEntry<'_>]) -> Result<Vec<u8>> {
        rar15_40::write_compressed_archive(
            entries,
            rar15_40::WriterOptions {
                target: self.target,
                features: self.features,
            },
        )
    }

    pub fn write_rar29_compressed_with_filter_policy(
        self,
        entries: &[rar15_40::FileEntry<'_>],
        policy: rar15_40::FilterPolicy,
    ) -> Result<Vec<u8>> {
        rar15_40::write_rar29_compressed_archive_with_filter_policy(
            entries,
            rar15_40::WriterOptions {
                target: self.target,
                features: self.features,
            },
            policy,
        )
    }

    pub fn write_rar15_compressed_with_comment(
        self,
        entries: &[rar15_40::FileEntry<'_>],
        archive_comment: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        rar15_40::write_compressed_archive_with_comment(
            entries,
            rar15_40::WriterOptions {
                target: self.target,
                features: self.features,
            },
            archive_comment,
        )
    }

    pub fn write_rar15_stored_volumes(
        self,
        entry: rar15_40::StoredEntry<'_>,
        max_packed_per_volume: usize,
    ) -> Result<Vec<Vec<u8>>> {
        rar15_40::write_stored_volumes(
            entry,
            rar15_40::WriterOptions {
                target: self.target,
                features: self.features,
            },
            max_packed_per_volume,
        )
    }

    pub fn write_rar15_compressed_volumes(
        self,
        entry: rar15_40::FileEntry<'_>,
        max_packed_per_volume: usize,
    ) -> Result<Vec<Vec<u8>>> {
        rar15_40::write_compressed_volumes(
            entry,
            rar15_40::WriterOptions {
                target: self.target,
                features: self.features,
            },
            max_packed_per_volume,
        )
    }

    pub fn rar50_options(self) -> Result<rar50::WriterOptions> {
        if self.target.family() != ArchiveFamily::Rar50Plus {
            return Err(Error::UnsupportedVersion(self.target));
        }
        Ok(rar50::WriterOptions {
            target: self.target,
            features: self.features,
        })
    }

    pub fn rar50_writer<'a>(self) -> Result<rar50::Rar50Writer<'a>> {
        Ok(rar50::Rar50Writer::new(self.rar50_options()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_rar29_filter(
        writer: ArchiveWriter,
        entries: &[rar15_40::FileEntry<'_>],
        kind: rar15_40::FilterKind,
    ) -> Result<Vec<u8>> {
        writer.write_rar29_compressed_with_filter_policy(
            entries,
            rar15_40::FilterPolicy::Explicit(rar15_40::FilterSpec::whole(kind)),
        )
    }

    fn write_rar29_filter_range(
        writer: ArchiveWriter,
        entries: &[rar15_40::FileEntry<'_>],
        kind: rar15_40::FilterKind,
        range: std::ops::Range<usize>,
    ) -> Result<Vec<u8>> {
        writer.write_rar29_compressed_with_filter_policy(
            entries,
            rar15_40::FilterPolicy::Explicit(rar15_40::FilterSpec::range(kind, range)),
        )
    }

    fn assert_rar50_volume_recovery_records(archives: &[rar50::Archive], percent: u64) {
        assert!(archives.iter().all(|archive| archive.main.is_volume()));
        assert!(archives
            .iter()
            .all(|archive| archive.main.has_recovery_record()));
        for archive in archives {
            let service = archive.services().next().unwrap();
            assert_eq!(service.name, b"RR");
            assert_eq!(service.recovery_record().unwrap().unwrap().percent, percent);
            let data = service.extract(archive).unwrap().data;
            assert!(data.starts_with(b"{RB}"));
            assert_eq!(
                u32::from_le_bytes(data[0x0c..0x10].try_into().unwrap()) as usize,
                data.len()
            );
        }
    }

    #[test]
    fn archive_writer_creates_rar15_stored_archive() {
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar15)
            .unwrap()
            .write_rar15_stored(&[rar15_40::StoredEntry {
                name: b"hello.txt",
                data: b"hello via facade\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }])
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].data, b"hello via facade\n");
    }

    #[test]
    fn archive_writer_keeps_rar13_methods_version_typed() {
        let err = ArchiveWriter::new(ArchiveVersion::Rar15)
            .unwrap()
            .write_stored(&[])
            .unwrap_err();

        assert!(matches!(
            err,
            Error::UnsupportedVersion(ArchiveVersion::Rar15)
        ));
    }

    #[test]
    fn archive_members_exposes_rar13_common_metadata_and_typed_detail() {
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar14)
            .unwrap()
            .write_stored(&[rar13::StoredEntry {
                name: b"old.txt",
                data: b"old rar member",
                file_time: 0x1234_5678,
                file_attr: 0x20,
                password: None,
                file_comment: Some(b"note"),
            }])
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let members: Vec<_> = archive.members().collect();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].meta.family, ArchiveFamily::Rar13);
        assert_eq!(members[0].meta.name, b"old.txt");
        assert_eq!(members[0].meta.packed_size, b"old rar member".len() as u64);
        assert_eq!(
            members[0].meta.unpacked_size,
            b"old rar member".len() as u64
        );
        assert_eq!(members[0].meta.file_time, Some(0x1234_5678));
        assert_eq!(members[0].meta.file_attr, 0x20);
        assert_eq!(members[0].meta.host_os, None);
        assert!(members[0].meta.is_stored);
        assert!(!members[0].meta.is_encrypted);
        assert!(!members[0].meta.is_split_before);
        assert!(!members[0].meta.is_split_after);
        assert!(matches!(
            members[0].detail,
            ArchiveMemberDetail::Rar13 {
                method: 0,
                unpack_version: _,
                file_checksum: _,
                has_file_comment: true,
            }
        ));
    }

    #[test]
    fn archive_members_exposes_rar15_40_common_metadata_and_typed_detail() {
        let mut features = FeatureSet::store_only();
        features.file_comment = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar29)
            .unwrap()
            .with_features(features)
            .write_rar15_compressed(&[rar15_40::FileEntry {
                name: b"newer.txt",
                data: b"rar 2.9 member metadata",
                file_time: 0x0102_0304,
                file_attr: 0x20,
                host_os: 2,
                password: None,
                file_comment: Some(b"rar29 note"),
            }])
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let members: Vec<_> = archive.members().collect();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].meta.family, ArchiveFamily::Rar15To40);
        assert_eq!(members[0].meta.name, b"newer.txt");
        assert_eq!(
            members[0].meta.unpacked_size,
            b"rar 2.9 member metadata".len() as u64
        );
        assert_eq!(members[0].meta.file_time, Some(0x0102_0304));
        assert_eq!(members[0].meta.file_attr, 0x20);
        assert_eq!(members[0].meta.host_os, Some(2));
        assert!(!members[0].meta.is_stored);
        assert!(!members[0].meta.is_encrypted);
        assert!(matches!(
            members[0].detail,
            ArchiveMemberDetail::Rar15To40 {
                method: 0x33 | 0x35,
                unpack_version: 29,
                crc32: _,
                solid: false,
                salt: None,
                has_file_comment: true,
            }
        ));
    }

    #[test]
    fn archive_members_exposes_rar50_common_metadata_and_typed_detail() {
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .rar50_writer()
            .unwrap()
            .stored_entries(&[rar50::StoredEntry {
                name: b"five.txt",
                data: b"rar 5 member metadata",
                mtime: Some(0x1111_2222),
                attributes: 0x1_0000_0020,
                host_os: 3,
            }])
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let members: Vec<_> = archive.members().collect();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].meta.family, ArchiveFamily::Rar50Plus);
        assert_eq!(members[0].meta.name, b"five.txt");
        assert_eq!(
            members[0].meta.packed_size,
            b"rar 5 member metadata".len() as u64
        );
        assert_eq!(
            members[0].meta.unpacked_size,
            b"rar 5 member metadata".len() as u64
        );
        assert_eq!(members[0].meta.file_time, Some(0x1111_2222));
        assert_eq!(members[0].meta.file_attr, 0x1_0000_0020);
        assert_eq!(members[0].meta.host_os, Some(3));
        assert!(members[0].meta.is_stored);
        assert!(!members[0].meta.is_encrypted);
        assert!(matches!(
            members[0].detail,
            ArchiveMemberDetail::Rar50Plus {
                compression_info: _,
                crc32: _,
                hash: _,
            }
        ));
    }

    #[test]
    fn archive_writer_creates_rar15_compressed_archive() {
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar15)
            .unwrap()
            .write_rar15_compressed(&[rar15_40::FileEntry {
                name: b"text.txt",
                data: b"facade compressed facade compressed facade compressed\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }])
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
        let extracted = archive.extract(None).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade compressed facade compressed facade compressed\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar29_compressed_archive_with_default_auto_policy() {
        let payload =
            b"facade rar29 default auto text alpha beta gamma alpha beta gamma\n".repeat(256);
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar29)
            .unwrap()
            .write_rar15_compressed(&[rar15_40::FileEntry {
                name: b"rar29-default-auto.txt",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }])
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert_eq!(raw.files().next().unwrap().method, 0x35);
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar29_e8_filtered_compressed_archive() {
        let payload = b"\xe8\0\0\0\0facade rar29 e8 filter payload\n".repeat(12);
        let bytes = write_rar29_filter(
            ArchiveWriter::new(ArchiveVersion::Rar29).unwrap(),
            &[rar15_40::FileEntry {
                name: b"rar29-e8.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::E8,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar29_auto_filtered_compressed_archive() {
        let payload = b"\xe8\0\0\0\0facade rar29 auto filter payload\n".repeat(12);
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar29)
            .unwrap()
            .write_rar29_compressed_with_filter_policy(
                &[rar15_40::FileEntry {
                    name: b"rar29-auto.bin",
                    data: &payload,
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                }],
                rar15_40::FilterPolicy::Auto,
            )
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar29_ppmd_compressed_archive() {
        let payload = b"facade rar29 ppmd text payload alpha beta gamma\n".repeat(64);
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar29)
            .unwrap()
            .write_rar29_compressed_with_filter_policy(
                &[rar15_40::FileEntry {
                    name: b"rar29-ppmd.txt",
                    data: &payload,
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                }],
                rar15_40::FilterPolicy::Ppmd,
            )
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.method, 0x35);
        assert_eq!(archive.extract(None).unwrap()[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar29_segmented_e8_filtered_compressed_archive() {
        let mut payload = b"facade unfiltered prefix before x86 segment ".to_vec();
        let filter_start = payload.len();
        payload.extend_from_slice(b"\xe8\0\0\0\0facade segmented e8 filter payload\n");
        let filter_end = payload.len();
        payload.extend_from_slice(b"facade unfiltered suffix after x86 segment\n");
        let bytes = write_rar29_filter_range(
            ArchiveWriter::new(ArchiveVersion::Rar29).unwrap(),
            &[rar15_40::FileEntry {
                name: b"rar29-segmented-e8.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::E8,
            filter_start..filter_end,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar29_solid_e8_filtered_compressed_archive() {
        let first = b"\xe8\0\0\0\0facade rar29 solid e8 first payload\n".repeat(12);
        let second = b"\xe8\0\0\0\0facade rar29 solid e8 second payload\n".repeat(12);
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let bytes = write_rar29_filter(
            ArchiveWriter::new(ArchiveVersion::Rar29)
                .unwrap()
                .with_features(features),
            &[
                rar15_40::FileEntry {
                    name: b"rar29-solid-e8-first.bin",
                    data: &first,
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
                rar15_40::FileEntry {
                    name: b"rar29-solid-e8-second.bin",
                    data: &second,
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
            ],
            rar15_40::FilterKind::E8,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let files: Vec<_> = raw.files().collect();
        assert!(raw.main.is_solid());
        assert!(!files[0].is_solid());
        assert!(files[1].is_solid());
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, first);
        assert_eq!(extracted[1].data, second);
    }

    #[test]
    fn archive_writer_creates_rar29_encrypted_e8_filtered_compressed_archive() {
        let payload = b"\xe8\0\0\0\0facade rar29 encrypted e8 payload\n".repeat(12);
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let bytes = write_rar29_filter(
            ArchiveWriter::new(ArchiveVersion::Rar29)
                .unwrap()
                .with_features(features),
            &[rar15_40::FileEntry {
                name: b"rar29-encrypted-e8.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }],
            rar15_40::FilterKind::E8,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert!(file.is_encrypted());
        assert!(file.salt.is_some());
        assert!(matches!(
            archive.extract(Some(b"wrong")),
            Err(Error::WrongPasswordOrCorruptData)
        ));
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar30_header_encrypted_e8_filtered_compressed_archive() {
        let payload = b"\xe8\0\0\0\0facade rar30 header encrypted e8 payload\n".repeat(12);
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let bytes = write_rar29_filter(
            ArchiveWriter::new(ArchiveVersion::Rar30)
                .unwrap()
                .with_features(features),
            &[rar15_40::FileEntry {
                name: b"rar30-header-encrypted-e8.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }],
            rar15_40::FilterKind::E8,
        )
        .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(raw.main.has_encrypted_headers());
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar29_e8e9_filtered_compressed_archive() {
        let payload = b"\xe9\0\0\0\0facade rar29 e8e9 filter payload\n".repeat(12);
        let bytes = write_rar29_filter(
            ArchiveWriter::new(ArchiveVersion::Rar29).unwrap(),
            &[rar15_40::FileEntry {
                name: b"rar29-e8e9.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::E8E9,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar29_delta_filtered_compressed_archive() {
        let payload: Vec<u8> = (0..384).map(|index| (index * 19 + 5) as u8).collect();
        let bytes = write_rar29_filter(
            ArchiveWriter::new(ArchiveVersion::Rar29).unwrap(),
            &[rar15_40::FileEntry {
                name: b"rar29-delta.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Delta { channels: 3 },
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar29_segmented_delta_filtered_compressed_archive() {
        let mut payload = b"facade unfiltered prefix before delta segment ".to_vec();
        let filter_start = payload.len();
        payload.extend((0..384).map(|index| (index * 19 + 5) as u8));
        let filter_end = payload.len();
        payload.extend_from_slice(b"facade unfiltered suffix after delta segment\n");
        let bytes = write_rar29_filter_range(
            ArchiveWriter::new(ArchiveVersion::Rar29).unwrap(),
            &[rar15_40::FileEntry {
                name: b"rar29-segmented-delta.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Delta { channels: 3 },
            filter_start..filter_end,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar29_itanium_filtered_compressed_archive() {
        let mut payload = vec![0u8; 48];
        payload[16] = 22;
        payload[21] = 20;
        payload.extend_from_slice(b"facade rar29 itanium filter payload\n");
        let bytes = write_rar29_filter(
            ArchiveWriter::new(ArchiveVersion::Rar29).unwrap(),
            &[rar15_40::FileEntry {
                name: b"rar29-itanium.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Itanium,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar29_segmented_itanium_filtered_compressed_archive() {
        let mut payload = b"facade unfiltered prefix before itanium segment ".to_vec();
        let filter_start = payload.len();
        payload.extend_from_slice(&[0; 48]);
        payload[filter_start + 16] = 22;
        payload[filter_start + 21] = 20;
        payload.extend_from_slice(b"facade segmented itanium filter payload\n");
        let filter_end = payload.len();
        payload.extend_from_slice(b"facade unfiltered suffix after itanium segment\n");
        let bytes = write_rar29_filter_range(
            ArchiveWriter::new(ArchiveVersion::Rar29).unwrap(),
            &[rar15_40::FileEntry {
                name: b"rar29-segmented-itanium.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Itanium,
            filter_start..filter_end,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar29_rgb_filtered_compressed_archive() {
        let width = 12;
        let payload: Vec<u8> = (0..96).map(|index| (index * 37 + 17) as u8).collect();
        let bytes = write_rar29_filter(
            ArchiveWriter::new(ArchiveVersion::Rar29).unwrap(),
            &[rar15_40::FileEntry {
                name: b"rar29-rgb.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Rgb { width, pos_r: 0 },
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar29_segmented_rgb_filtered_compressed_archive() {
        let width = 12;
        let mut payload = b"facade unfiltered prefix before rgb segment ".to_vec();
        let filter_start = payload.len();
        payload.extend((0..96).map(|index| (index * 37 + 17) as u8));
        let filter_end = payload.len();
        payload.extend_from_slice(b"facade unfiltered suffix after rgb segment\n");
        let bytes = write_rar29_filter_range(
            ArchiveWriter::new(ArchiveVersion::Rar29).unwrap(),
            &[rar15_40::FileEntry {
                name: b"rar29-segmented-rgb.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Rgb { width, pos_r: 0 },
            filter_start..filter_end,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar29_audio_filtered_compressed_archive() {
        let payload: Vec<u8> = (0..160)
            .map(|index| (index * 11 + index / 7) as u8)
            .collect();
        let bytes = write_rar29_filter(
            ArchiveWriter::new(ArchiveVersion::Rar29).unwrap(),
            &[rar15_40::FileEntry {
                name: b"rar29-audio.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Audio { channels: 2 },
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar29_segmented_audio_filtered_compressed_archive() {
        let mut payload = b"facade unfiltered prefix before audio segment ".to_vec();
        let filter_start = payload.len();
        payload.extend((0..160).map(|index| (index * 11 + index / 7) as u8));
        let filter_end = payload.len();
        payload.extend_from_slice(b"facade unfiltered suffix after audio segment\n");
        let bytes = write_rar29_filter_range(
            ArchiveWriter::new(ArchiveVersion::Rar29).unwrap(),
            &[rar15_40::FileEntry {
                name: b"rar29-segmented-audio.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Audio { channels: 2 },
            filter_start..filter_end,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar20_compressed_archive() {
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar20)
            .unwrap()
            .write_rar15_compressed(&[rar15_40::FileEntry {
                name: b"rar20.txt",
                data: b"facade rar20 literal compressed payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }])
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.unp_ver, 20);
        assert_eq!(file.method, 0x33);
        assert_eq!(
            archive.extract(None).unwrap()[0].data,
            b"facade rar20 literal compressed payload\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar29_compressed_archive() {
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar29)
            .unwrap()
            .write_rar15_compressed(&[rar15_40::FileEntry {
                name: b"rar29.txt",
                data: b"facade rar29 literal compressed payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }])
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.unp_ver, 29);
        assert!(matches!(file.method, 0x33 | 0x35));
        assert_eq!(
            archive.extract(None).unwrap()[0].data,
            b"facade rar29 literal compressed payload\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar29_solid_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar29)
            .unwrap()
            .with_features(features)
            .write_rar15_compressed(&[
                rar15_40::FileEntry {
                    name: b"one.txt",
                    data: b"facade rar29 solid one alpha beta\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
                rar15_40::FileEntry {
                    name: b"two.txt",
                    data: b"facade rar29 solid two alpha beta\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
            ])
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(raw.main.is_solid());
        let files: Vec<_> = raw.files().collect();
        assert!(!files[0].is_solid());
        assert!(files[1].is_solid());
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar29 solid one alpha beta\n");
        assert_eq!(extracted[1].data, b"facade rar29 solid two alpha beta\n");
    }

    #[test]
    fn archive_writer_creates_rar20_solid_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let first = b"facade rar20 solid shared line alpha beta gamma\n".repeat(48);
        let second = b"facade rar20 solid shared line alpha beta gamma\nsecond\n".repeat(24);
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar20)
            .unwrap()
            .with_features(features)
            .write_rar15_compressed(&[
                rar15_40::FileEntry {
                    name: b"one.txt",
                    data: &first,
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
                rar15_40::FileEntry {
                    name: b"two.txt",
                    data: &second,
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
            ])
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(raw.main.is_solid());
        let files: Vec<_> = raw.files().collect();
        assert_eq!(files[0].unp_ver, 20);
        assert_eq!(files[1].unp_ver, 20);
        assert!(!files[0].is_solid());
        assert!(files[1].is_solid());
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, first);
        assert_eq!(extracted[1].data, second);
    }

    #[test]
    fn archive_writer_creates_rar15_archive_comment() {
        let mut features = FeatureSet::store_only();
        features.archive_comment = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar15)
            .unwrap()
            .with_features(features)
            .write_rar15_compressed_with_comment(
                &[rar15_40::FileEntry {
                    name: b"commented.txt",
                    data: b"facade commented payload\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                }],
                Some(b"facade note\n"),
            )
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let archive = archive.as_rar15_40().unwrap();
        assert_eq!(
            archive.archive_comment().unwrap().as_deref(),
            Some(&b"facade note\n"[..])
        );
        assert_eq!(
            archive.extract().unwrap()[0].data,
            b"facade commented payload\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar15_file_comment() {
        let mut features = FeatureSet::store_only();
        features.file_comment = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar15)
            .unwrap()
            .with_features(features)
            .write_rar15_stored(&[rar15_40::StoredEntry {
                name: b"file-comment.txt",
                data: b"facade file comment payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: Some(b"facade file note"),
            }])
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let archive = archive.as_rar15_40().unwrap();
        let file = archive.files().next().unwrap();
        assert_eq!(
            file.file_comment().unwrap().as_deref(),
            Some(&b"facade file note"[..])
        );
        assert_eq!(
            archive.extract().unwrap()[0].data,
            b"facade file comment payload\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar20_old_style_comments() {
        let mut archive_features = FeatureSet::store_only();
        archive_features.archive_comment = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar20)
            .unwrap()
            .with_features(archive_features)
            .write_rar15_compressed_with_comment(
                &[rar15_40::FileEntry {
                    name: b"rar20-commented.txt",
                    data: b"facade rar20 archive comment payload\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                }],
                Some(b"facade rar20 archive note"),
            )
            .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(raw.main.has_archive_comment());
        assert_eq!(
            raw.archive_comment().unwrap().as_deref(),
            Some(b"facade rar20 archive note".as_slice())
        );

        let mut file_features = FeatureSet::store_only();
        file_features.file_comment = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar20)
            .unwrap()
            .with_features(file_features)
            .write_rar15_compressed(&[rar15_40::FileEntry {
                name: b"rar20-file-commented.txt",
                data: b"facade rar20 file comment payload payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: Some(b"facade rar20 file note"),
            }])
            .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.unp_ver, 20);
        assert_eq!(
            file.file_comment().unwrap().as_deref(),
            Some(b"facade rar20 file note".as_slice())
        );
    }

    #[test]
    fn archive_writer_creates_rar29_old_style_comments() {
        let mut archive_features = FeatureSet::store_only();
        archive_features.archive_comment = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar29)
            .unwrap()
            .with_features(archive_features)
            .write_rar15_compressed_with_comment(
                &[rar15_40::FileEntry {
                    name: b"rar29-commented.txt",
                    data: b"facade rar29 archive comment payload\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                }],
                Some(b"facade rar29 archive note"),
            )
            .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(raw.main.has_archive_comment());
        assert_eq!(
            raw.archive_comment().unwrap().as_deref(),
            Some(b"facade rar29 archive note".as_slice())
        );

        let mut file_features = FeatureSet::store_only();
        file_features.file_comment = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar29)
            .unwrap()
            .with_features(file_features)
            .write_rar15_compressed(&[rar15_40::FileEntry {
                name: b"rar29-file-commented.txt",
                data: b"facade rar29 file comment payload payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: Some(b"facade rar29 file note"),
            }])
            .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.unp_ver, 29);
        assert_eq!(
            file.file_comment().unwrap().as_deref(),
            Some(b"facade rar29 file note".as_slice())
        );
    }

    #[test]
    fn archive_writer_creates_rar30_newsub_archive_comment() {
        let mut features = FeatureSet::store_only();
        features.archive_comment = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar30)
            .unwrap()
            .with_features(features)
            .write_rar15_compressed_with_comment(
                &[rar15_40::FileEntry {
                    name: b"rar30-commented.txt",
                    data: b"facade rar30 NEWSUB archive comment payload\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                }],
                Some(b"facade rar30 NEWSUB note"),
            )
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(!raw.main.has_archive_comment());
        let subblock = raw.new_subs().next().unwrap();
        assert_eq!(subblock.kind, rar15_40::NewSubKind::ArchiveComment);
        assert_eq!(subblock.file.name, b"CMT");
        assert_eq!(
            raw.archive_comment().unwrap().as_deref(),
            Some(b"facade rar30 NEWSUB note".as_slice())
        );
    }

    #[test]
    fn archive_writer_creates_rar15_solid_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar15)
            .unwrap()
            .with_features(features)
            .write_rar15_compressed(&[
                rar15_40::FileEntry {
                    name: b"one.txt",
                    data: b"shared facade prefix one\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
                rar15_40::FileEntry {
                    name: b"two.txt",
                    data: b"shared facade prefix two\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
            ])
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, b"shared facade prefix one\n");
        assert_eq!(extracted[1].data, b"shared facade prefix two\n");
    }

    #[test]
    fn archive_writer_creates_rar15_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar15)
            .unwrap()
            .with_features(features)
            .write_rar15_compressed(&[rar15_40::FileEntry {
                name: b"secret.txt",
                data: b"facade encrypted payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }])
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert!(matches!(archive.extract(None), Err(Error::NeedPassword)));
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, b"facade encrypted payload\n");
    }

    #[test]
    fn archive_writer_creates_rar15_stored_volumes() {
        let parts = ArchiveWriter::new(ArchiveVersion::Rar15)
            .unwrap()
            .write_rar15_stored_volumes(
                rar15_40::StoredEntry {
                    name: b"split.bin",
                    data: b"abcdefghijklmnopqrstuvwxyz0123456789",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
                10,
            )
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();
        let extracted = rar15_40::extract_volumes(&archives).unwrap();

        assert_eq!(extracted[0].name, b"split.bin");
        assert_eq!(extracted[0].data, b"abcdefghijklmnopqrstuvwxyz0123456789");
    }

    #[test]
    fn archive_writer_creates_rar20_compressed_volumes() {
        let data = b"facade rar20 split phrase alpha beta gamma\n".repeat(32);
        let parts = ArchiveWriter::new(ArchiveVersion::Rar20)
            .unwrap()
            .write_rar15_compressed_volumes(
                rar15_40::FileEntry {
                    name: b"split-rar20.txt",
                    data: &data,
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
                8,
            )
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();
        let first_file = archives[0].files().next().unwrap();
        assert_eq!(first_file.unp_ver, 20);
        assert!(first_file.is_split_after());

        let extracted = rar15_40::extract_volumes(&archives).unwrap();
        assert_eq!(extracted[0].name, b"split-rar20.txt");
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn archive_writer_creates_rar29_compressed_volumes() {
        let data = b"facade rar29 split phrase alpha beta gamma\n".repeat(32);
        let parts = ArchiveWriter::new(ArchiveVersion::Rar29)
            .unwrap()
            .write_rar15_compressed_volumes(
                rar15_40::FileEntry {
                    name: b"split-rar29.txt",
                    data: &data,
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
                8,
            )
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();
        let first_file = archives[0].files().next().unwrap();
        assert_eq!(first_file.unp_ver, 29);
        assert!(first_file.is_split_after());

        let extracted = rar15_40::extract_volumes(&archives).unwrap();
        assert_eq!(extracted[0].name, b"split-rar29.txt");
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn archive_writer_creates_rar29_encrypted_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let parts = ArchiveWriter::new(ArchiveVersion::Rar29)
            .unwrap()
            .with_features(features)
            .write_rar15_compressed_volumes(
                rar15_40::FileEntry {
                    name: b"split-rar29-secret.txt",
                    data: b"facade rar29 encrypted split facade rar29 encrypted split\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: Some(b"password"),
                    file_comment: None,
                },
                8,
            )
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();

        assert!(matches!(
            rar15_40::extract_volumes(&archives),
            Err(Error::NeedPassword)
        ));
        let extracted =
            rar15_40::extract_volumes_with_password(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-rar29-secret.txt");
        assert_eq!(
            extracted[0].data,
            b"facade rar29 encrypted split facade rar29 encrypted split\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar15_encrypted_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let parts = ArchiveWriter::new(ArchiveVersion::Rar15)
            .unwrap()
            .with_features(features)
            .write_rar15_compressed_volumes(
                rar15_40::FileEntry {
                    name: b"split-secret.txt",
                    data: b"facade encrypted split facade encrypted split\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: Some(b"password"),
                    file_comment: None,
                },
                8,
            )
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();

        assert!(matches!(
            rar15_40::extract_volumes(&archives),
            Err(Error::NeedPassword)
        ));
        let extracted =
            rar15_40::extract_volumes_with_password(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-secret.txt");
        assert_eq!(
            extracted[0].data,
            b"facade encrypted split facade encrypted split\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar30_encrypted_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let parts = ArchiveWriter::new(ArchiveVersion::Rar30)
            .unwrap()
            .with_features(features)
            .write_rar15_compressed_volumes(
                rar15_40::FileEntry {
                    name: b"split-rar30-secret.txt",
                    data: b"facade rar30 encrypted split facade rar30 encrypted split\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: Some(b"password"),
                    file_comment: None,
                },
                8,
            )
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();

        assert!(matches!(
            rar15_40::extract_volumes(&archives),
            Err(Error::NeedPassword)
        ));
        let extracted =
            rar15_40::extract_volumes_with_password(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-rar30-secret.txt");
        assert_eq!(
            extracted[0].data,
            b"facade rar30 encrypted split facade rar30 encrypted split\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar30_header_encrypted_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let parts = ArchiveWriter::new(ArchiveVersion::Rar30)
            .unwrap()
            .with_features(features)
            .write_rar15_compressed_volumes(
                rar15_40::FileEntry {
                    name: b"split-rar30-header-secret.txt",
                    data: b"facade rar30 header encrypted split facade rar30 header encrypted split\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: Some(b"password"),
                    file_comment: None,
                },
                8,
            )
            .unwrap();
        assert!(matches!(
            rar15_40::Archive::parse(&parts[0]),
            Err(Error::NeedPassword)
        ));
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();

        let extracted =
            rar15_40::extract_volumes_with_password(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-rar30-header-secret.txt");
        assert_eq!(
            extracted[0].data,
            b"facade rar30 header encrypted split facade rar30 header encrypted split\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar30_aes_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar30)
            .unwrap()
            .with_features(features)
            .write_rar15_compressed(&[rar15_40::FileEntry {
                name: b"rar30-secret.txt",
                data: b"facade rar30 aes encrypted payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }])
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert!(matches!(archive.extract(None), Err(Error::NeedPassword)));
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, b"facade rar30 aes encrypted payload\n");
    }

    #[test]
    fn archive_writer_creates_rar29_aes_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar29)
            .unwrap()
            .with_features(features)
            .write_rar15_compressed(&[rar15_40::FileEntry {
                name: b"rar29-secret.txt",
                data: b"facade rar29 aes encrypted payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }])
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.unp_ver, 29);
        assert!(file.is_encrypted());
        assert!(file.salt.is_some());
        assert!(matches!(archive.extract(None), Err(Error::NeedPassword)));
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, b"facade rar29 aes encrypted payload\n");
    }

    #[test]
    fn archive_writer_creates_rar20_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar20)
            .unwrap()
            .with_features(features)
            .write_rar15_compressed(&[rar15_40::FileEntry {
                name: b"rar20-secret.txt",
                data: b"facade rar20 encrypted payload payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }])
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.unp_ver, 20);
        assert!(file.is_encrypted());
        assert!(matches!(archive.extract(None), Err(Error::NeedPassword)));
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar20 encrypted payload payload\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar30_header_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar30)
            .unwrap()
            .with_features(features)
            .write_rar15_compressed(&[rar15_40::FileEntry {
                name: b"rar30-header-secret.txt",
                data: b"facade rar30 header encrypted payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }])
            .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(raw.main.has_encrypted_headers());
        assert_eq!(raw.files().next().unwrap().name, b"rar30-header-secret.txt");
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar30 header encrypted payload\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar30_solid_header_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.solid = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar30)
            .unwrap()
            .with_features(features)
            .write_rar15_compressed(&[
                rar15_40::FileEntry {
                    name: b"solid-header-one.txt",
                    data: b"facade solid header encrypted one one one\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: Some(b"password"),
                    file_comment: None,
                },
                rar15_40::FileEntry {
                    name: b"solid-header-two.txt",
                    data: b"facade solid header encrypted two two two\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: Some(b"password"),
                    file_comment: None,
                },
            ])
            .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade solid header encrypted one one one\n"
        );
        assert_eq!(
            extracted[1].data,
            b"facade solid header encrypted two two two\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar50_stored_archive() {
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .rar50_writer()
            .unwrap()
            .stored_entries(&[rar50::StoredEntry {
                name: b"rar5-store.txt",
                data: b"facade rar5 stored payload\n",
                mtime: Some(0),
                attributes: 0x20,
                host_os: 3,
            }])
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert_eq!(archive.family(), ArchiveFamily::Rar50Plus);
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 stored payload\n");
    }

    #[test]
    fn archive_writer_creates_rar50_compressed_archive() {
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .rar50_writer()
            .unwrap()
            .compressed_entries(&[rar50::CompressedEntry {
                name: b"rar5-compressed.txt",
                data: b"facade rar5 compressed payload\nfacade rar5 compressed payload\n",
                mtime: Some(0),
                attributes: 0x20,
                host_os: 3,
            }])
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.decoded_compression_info().unwrap().method, 1);
        let extracted = archive.extract(None).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 compressed payload\nfacade rar5 compressed payload\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar50_solid_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let first = b"facade rar50 solid shared phrase alpha beta gamma\n".repeat(16);
        let second = b"facade rar50 solid shared phrase alpha beta gamma\nsecond\n".repeat(8);
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .compressed_entries(&[
                rar50::CompressedEntry {
                    name: b"rar5-solid-one.txt",
                    data: &first,
                    mtime: Some(0),
                    attributes: 0x20,
                    host_os: 3,
                },
                rar50::CompressedEntry {
                    name: b"rar5-solid-two.txt",
                    data: &second,
                    mtime: Some(0),
                    attributes: 0x20,
                    host_os: 3,
                },
            ])
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let files: Vec<_> = raw.files().collect();
        assert!(raw.main.is_solid());
        assert!(!files[0].decoded_compression_info().unwrap().solid);
        assert!(files[1].decoded_compression_info().unwrap().solid);
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, first);
        assert_eq!(extracted[1].data, second);
    }

    #[test]
    fn archive_writer_creates_rar50_delta_filtered_compressed_archive() {
        let payload: Vec<u8> = (0..180)
            .map(|index| (index * 11 + index / 5) as u8)
            .collect();
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .rar50_writer()
            .unwrap()
            .compressed_entries(&[rar50::CompressedEntry {
                name: b"rar5-delta-filtered.bin",
                data: &payload,
                mtime: Some(0),
                attributes: 0x20,
                host_os: 3,
            }])
            .filter_policy(rar50::FilterPolicy::Explicit(rar50::FilterKind::Delta {
                channels: 3,
            }))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_e8_filtered_compressed_archive() {
        let payload = b"\xe8\0\0\0\0facade rar5 e8 filter payload".to_vec();
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .rar50_writer()
            .unwrap()
            .compressed_entries(&[rar50::CompressedEntry {
                name: b"rar5-e8-filtered.bin",
                data: &payload,
                mtime: Some(0),
                attributes: 0x20,
                host_os: 3,
            }])
            .filter_policy(rar50::FilterPolicy::Explicit(rar50::FilterKind::E8))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_arm_filtered_compressed_archive() {
        let payload = [0x04, 0x00, 0x00, 0xeb, b'A', b'R', b'M', b'!'];
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .rar50_writer()
            .unwrap()
            .compressed_entries(&[rar50::CompressedEntry {
                name: b"rar5-arm-filtered.bin",
                data: &payload,
                mtime: Some(0),
                attributes: 0x20,
                host_os: 3,
            }])
            .filter_policy(rar50::FilterPolicy::Explicit(rar50::FilterKind::Arm))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_auto_filtered_compressed_archive() {
        let payload = b"\xe8\0\0\0\0facade rar5 auto filter payload\n".repeat(16);
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .rar50_writer()
            .unwrap()
            .compressed_entries(&[rar50::CompressedEntry {
                name: b"rar5-auto-filtered.bin",
                data: &payload,
                mtime: Some(0),
                attributes: 0x20,
                host_os: 3,
            }])
            .filter_policy(rar50::FilterPolicy::AutoSize)
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_stored_archive_with_comment_service() {
        let mut features = FeatureSet::store_only();
        features.archive_comment = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .stored_entries(&[rar50::StoredEntry {
                name: b"rar5-commented.txt",
                data: b"facade rar5 comment payload\n",
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            }])
            .archive_comment(Some(b"facade rar5 comment\n"))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let services: Vec<_> = raw.services().collect();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, b"CMT");
        assert_eq!(
            services[0].extract(raw).unwrap().data,
            b"facade rar5 comment\n"
        );
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 comment payload\n");
    }

    #[test]
    fn archive_writer_creates_rar50_stored_file_comment_service() {
        let services = [rar50::StoredServiceEntry {
            name: b"CMT",
            data: b"facade rar5 file comment\n",
        }];
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .rar50_writer()
            .unwrap()
            .stored_entries_with_services(&[rar50::StoredEntryWithServices {
                entry: rar50::StoredEntry {
                    name: b"rar5-file-commented.txt",
                    data: b"facade rar5 file comment payload\n",
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                },
                services: &services,
            }])
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let services: Vec<_> = raw.services().collect();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, b"CMT");
        assert_eq!(
            services[0].extract(raw).unwrap().data,
            b"facade rar5 file comment\n"
        );
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 file comment payload\n");
    }

    #[test]
    fn archive_writer_creates_rar50_encrypted_stored_file_comment_service() {
        let services = [rar50::EncryptedStoredServiceEntry {
            name: b"CMT",
            data: b"facade encrypted rar5 file comment\n",
            password: b"password",
        }];
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.file_comment = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_stored_entries_with_services(&[rar50::EncryptedStoredEntryWithServices {
                entry: rar50::EncryptedStoredEntry {
                    name: b"rar5-encrypted-file-commented.txt",
                    data: b"facade encrypted rar5 file comment payload\n",
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                },
                services: &services,
            }])
            .finish()
            .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let service = raw.services().next().unwrap().extract(raw).unwrap();
        assert_eq!(service.data, b"facade encrypted rar5 file comment\n");
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade encrypted rar5 file comment payload\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar50_header_encrypted_stored_file_comment_service() {
        let services = [rar50::EncryptedStoredServiceEntry {
            name: b"CMT",
            data: b"facade header encrypted rar5 file comment\n",
            password: b"password",
        }];
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.file_comment = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_stored_entries_with_services(&[rar50::EncryptedStoredEntryWithServices {
                entry: rar50::EncryptedStoredEntry {
                    name: b"rar5-header-file-commented.txt",
                    data: b"facade header encrypted rar5 file comment payload\n",
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                },
                services: &services,
            }])
            .finish()
            .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let service = raw.services().next().unwrap().extract(raw).unwrap();
        assert_eq!(service.data, b"facade header encrypted rar5 file comment\n");
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade header encrypted rar5 file comment payload\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar50_stored_archive_with_quick_open_service() {
        let mut features = FeatureSet::store_only();
        features.quick_open = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .stored_entries(&[rar50::StoredEntry {
                name: b"rar5-qo.txt",
                data: b"facade rar5 quick-open payload\n",
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            }])
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.locator().unwrap().quick_open_offset.unwrap() > 0);
        let services: Vec<_> = raw.services().collect();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, b"QO");
        assert!(!services[0].extract(raw).unwrap().data.is_empty());
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 quick-open payload\n");
    }

    #[test]
    fn archive_writer_creates_rar50_stored_archive_with_file_services() {
        let services = [
            rar50::StoredServiceEntry {
                name: b"ACL",
                data: b"facade acl",
            },
            rar50::StoredServiceEntry {
                name: b"STM",
                data: b"facade stream",
            },
        ];
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .rar50_writer()
            .unwrap()
            .stored_entries_with_services(&[rar50::StoredEntryWithServices {
                entry: rar50::StoredEntry {
                    name: b"rar5-services.txt",
                    data: b"facade rar5 service payload\n",
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                },
                services: &services,
            }])
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let services: Vec<_> = raw.services().collect();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].name, b"ACL");
        assert_eq!(services[1].name, b"STM");
        assert_eq!(services[0].extract(raw).unwrap().data, b"facade acl");
        assert_eq!(services[1].extract(raw).unwrap().data, b"facade stream");
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 service payload\n");
    }

    #[test]
    fn archive_writer_creates_rar50_stored_archive_with_recovery_service() {
        let mut features = FeatureSet::store_only();
        features.recovery_record = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .stored_entries(&[rar50::StoredEntry {
                name: b"rar5-recovery.txt",
                data: b"facade rar5 recovery payload\n",
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            }])
            .recovery_percent(Some(9))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.has_recovery_record());
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"RR");
        let recovery = service.recovery_record().unwrap().unwrap();
        assert_eq!(recovery.percent, 9);
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 recovery payload\n");
    }

    #[test]
    fn archive_facade_repairs_rar50_inline_recovery_damage() {
        let mut features = FeatureSet::store_only();
        features.recovery_record = true;
        let payload = b"facade rar5 repair payload\n".repeat(64);
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .stored_entries(&[rar50::StoredEntry {
                name: b"rar5-repair.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            }])
            .recovery_percent(Some(20))
            .finish()
            .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let data_range = archive
            .as_rar50()
            .unwrap()
            .files()
            .next()
            .unwrap()
            .block
            .data_range
            .clone();
        let mut damaged = bytes.clone();
        damaged[data_range.start + 4..data_range.start + 80].fill(0xa5);
        let damaged_archive = ArchiveReader::read(&damaged).unwrap();
        assert!(damaged_archive.extract(None).is_err());

        let repaired = damaged_archive.repair_recovery().unwrap();

        assert_eq!(repaired, bytes);
        let repaired_archive = ArchiveReader::read(&repaired).unwrap();
        assert_eq!(repaired_archive.extract(None).unwrap()[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_compressed_archive_with_recovery_service() {
        let mut features = FeatureSet::store_only();
        features.recovery_record = true;
        let payload = b"facade rar5 compressed recovery payload repeated repeated\n".repeat(8);
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .compressed_entries(&[rar50::CompressedEntry {
                name: b"rar5-compressed-recovery.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            }])
            .recovery_percent(Some(9))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.has_recovery_record());
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"RR");
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 9);
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar70_stored_archive_with_metadata() {
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar70)
            .unwrap()
            .rar50_writer()
            .unwrap()
            .stored_entries(&[rar50::StoredEntry {
                name: b"rar7-metadata.txt",
                data: b"facade rar7 metadata payload\n",
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            }])
            .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                name: Some(b"facade-metadata.rar"),
                creation_time: Some(0x01dcd60e_662d7a32),
            }))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
        assert_eq!(
            metadata.name.as_deref(),
            Some(b"facade-metadata.rar".as_slice())
        );
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar7 metadata payload\n");
    }

    #[test]
    fn archive_writer_creates_rar70_compressed_archive_with_metadata() {
        let payload = b"facade rar7 compressed metadata payload repeated\n".repeat(8);
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar70)
            .unwrap()
            .rar50_writer()
            .unwrap()
            .compressed_entries(&[rar50::CompressedEntry {
                name: b"rar7-compressed-metadata.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            }])
            .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                name: Some(b"facade-compressed-metadata.rar"),
                creation_time: Some(0x01dcd60e_662d7a32),
            }))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
        assert_eq!(
            metadata.name.as_deref(),
            Some(b"facade-compressed-metadata.rar".as_slice())
        );
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_compressed_archive_with_comment() {
        let payload = b"facade rar5 compressed archive comment payload repeated\n".repeat(8);
        let mut features = FeatureSet::store_only();
        features.archive_comment = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .compressed_entries(&[rar50::CompressedEntry {
                name: b"rar5-compressed-comment.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            }])
            .archive_comment(Some(b"facade compressed comment\n"))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let comment = raw.services().next().unwrap().extract(raw).unwrap();
        assert_eq!(comment.data, b"facade compressed comment\n");
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar70_encrypted_stored_archive_with_metadata() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar70)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_stored_entries(&[rar50::EncryptedStoredEntry {
                name: b"rar7-encrypted-metadata.txt",
                data: b"facade rar7 encrypted metadata payload\n",
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }])
            .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                name: Some(b"facade-encrypted-metadata.rar"),
                creation_time: Some(0x01dcd60e_662d7a32),
            }))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
        assert_eq!(
            metadata.name.as_deref(),
            Some(b"facade-encrypted-metadata.rar".as_slice())
        );
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar7 encrypted metadata payload\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar70_encrypted_compressed_archive_with_metadata() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let payload = b"facade rar7 encrypted compressed metadata payload repeated\n".repeat(8);
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar70)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_compressed_entries(&[rar50::EncryptedCompressedEntry {
                name: b"rar7-encrypted-compressed-metadata.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }])
            .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                name: Some(b"facade-encrypted-compressed-metadata.rar"),
                creation_time: Some(0x01dcd60e_662d7a32),
            }))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
        assert_eq!(
            metadata.name.as_deref(),
            Some(b"facade-encrypted-compressed-metadata.rar".as_slice())
        );
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar70_header_encrypted_stored_archive_with_metadata() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar70)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_stored_entries(&[rar50::EncryptedStoredEntry {
                name: b"rar7-header-metadata.txt",
                data: b"facade rar7 header encrypted metadata payload\n",
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }])
            .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                name: Some(b"facade-header-metadata.rar"),
                creation_time: Some(0x01dcd60e_662d7a32),
            }))
            .finish()
            .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
        assert_eq!(
            metadata.name.as_deref(),
            Some(b"facade-header-metadata.rar".as_slice())
        );
        let extracted = archive.extract(None).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar7 header encrypted metadata payload\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar70_header_encrypted_compressed_archive_with_metadata() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let payload =
            b"facade rar7 header encrypted compressed metadata payload repeated\n".repeat(8);
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar70)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_compressed_entries(&[rar50::EncryptedCompressedEntry {
                name: b"rar7-header-compressed-metadata.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }])
            .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                name: Some(b"facade-header-compressed-metadata.rar"),
                creation_time: Some(0x01dcd60e_662d7a32),
            }))
            .finish()
            .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
        assert_eq!(
            metadata.name.as_deref(),
            Some(b"facade-header-compressed-metadata.rar".as_slice())
        );
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_encrypted_stored_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_stored_entries(&[rar50::EncryptedStoredEntry {
                name: b"rar5-secret.txt",
                data: b"facade rar5 encrypted stored payload\n",
                mtime: Some(0),
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }])
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert!(matches!(
            archive.extract(None),
            Err(Error::AtEntry { source, .. }) if matches!(*source, Error::NeedPassword)
        ));
        assert!(matches!(
            archive.extract(Some(b"wrong")),
            Err(Error::AtEntry { source, .. })
                if matches!(*source, Error::WrongPasswordOrCorruptData)
        ));
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 encrypted stored payload\n");
    }

    #[test]
    fn archive_writer_creates_rar50_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_compressed_entries(&[rar50::EncryptedCompressedEntry {
                name: b"rar5-secret-compressed.txt",
                data: b"facade rar5 encrypted compressed\nfacade rar5 encrypted compressed\n",
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }])
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let file = raw.files().next().unwrap();
        assert!(file.encrypted);
        assert_eq!(file.decoded_compression_info().unwrap().method, 1);
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 encrypted compressed\nfacade rar5 encrypted compressed\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar50_encrypted_solid_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.solid = true;
        let first = b"facade rar50 encrypted solid shared phrase alpha beta gamma\n".repeat(12);
        let second =
            b"facade rar50 encrypted solid shared phrase alpha beta gamma\nsecond\n".repeat(6);
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_compressed_entries(&[
                rar50::EncryptedCompressedEntry {
                    name: b"rar5-encrypted-solid-one.txt",
                    data: &first,
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                },
                rar50::EncryptedCompressedEntry {
                    name: b"rar5-encrypted-solid-two.txt",
                    data: &second,
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                },
            ])
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let files: Vec<_> = raw.files().collect();
        assert!(raw.main.is_solid());
        assert!(files.iter().all(|file| file.encrypted));
        assert!(!files[0].decoded_compression_info().unwrap().solid);
        assert!(files[1].decoded_compression_info().unwrap().solid);
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, first);
        assert_eq!(extracted[1].data, second);
    }

    #[test]
    fn archive_writer_creates_rar50_header_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_compressed_entries(&[rar50::EncryptedCompressedEntry {
                name: b"rar5-header-secret-compressed.txt",
                data: b"facade rar5 header encrypted compressed\nfacade rar5 header encrypted compressed\n",
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }])
            .finish()
            .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let file = raw.files().next().unwrap();
        assert!(file.encrypted);
        assert_eq!(file.decoded_compression_info().unwrap().method, 1);
        let extracted = archive.extract(None).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 header encrypted compressed\nfacade rar5 header encrypted compressed\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar50_header_encrypted_solid_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.solid = true;
        let first =
            b"facade rar50 header encrypted solid shared phrase alpha beta gamma\n".repeat(12);
        let second =
            b"facade rar50 header encrypted solid shared phrase alpha beta gamma\nsecond\n"
                .repeat(6);
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_compressed_entries(&[
                rar50::EncryptedCompressedEntry {
                    name: b"rar5-header-solid-one.txt",
                    data: &first,
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                },
                rar50::EncryptedCompressedEntry {
                    name: b"rar5-header-solid-two.txt",
                    data: &second,
                    mtime: None,
                    attributes: 0x20,
                    host_os: 3,
                    password: b"password",
                },
            ])
            .finish()
            .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let files: Vec<_> = raw.files().collect();
        assert!(raw.main.is_solid());
        assert!(files.iter().all(|file| file.encrypted));
        assert!(!files[0].decoded_compression_info().unwrap().solid);
        assert!(files[1].decoded_compression_info().unwrap().solid);
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, first);
        assert_eq!(extracted[1].data, second);
    }

    #[test]
    fn archive_writer_creates_rar50_encrypted_stored_archive_with_comment() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.archive_comment = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_stored_entries(&[rar50::EncryptedStoredEntry {
                name: b"rar5-secret.txt",
                data: b"facade rar5 encrypted stored payload\n",
                mtime: Some(0),
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }])
            .encrypted_archive_comment(Some(rar50::EncryptedArchiveCommentEntry {
                data: b"facade encrypted comment\n",
                password: b"password",
            }))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let comment = raw.services().next().unwrap().extract(raw).unwrap();
        assert_eq!(comment.data, b"facade encrypted comment\n");
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 encrypted stored payload\n");
    }

    #[test]
    fn archive_writer_creates_rar50_encrypted_compressed_archive_with_comment() {
        let payload = b"facade rar5 encrypted compressed comment payload\n".repeat(8);
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.archive_comment = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_compressed_entries(&[rar50::EncryptedCompressedEntry {
                name: b"rar5-encrypted-compressed-comment.txt",
                data: &payload,
                mtime: Some(0),
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }])
            .encrypted_archive_comment(Some(rar50::EncryptedArchiveCommentEntry {
                data: b"facade encrypted compressed comment\n",
                password: b"password",
            }))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let comment = raw.services().next().unwrap().extract(raw).unwrap();
        assert_eq!(comment.data, b"facade encrypted compressed comment\n");
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_header_encrypted_stored_archive() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_stored_entries(&[rar50::EncryptedStoredEntry {
                name: b"rar5-header-secret.txt",
                data: b"facade rar5 header encrypted stored payload\n",
                mtime: Some(0),
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }])
            .finish()
            .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        assert!(matches!(
            ArchiveReader::read_with_options(&bytes, ArchiveReadOptions::with_password(b"wrong")),
            Err(Error::WrongPasswordOrCorruptData)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 header encrypted stored payload\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar50_header_encrypted_stored_archive_with_comment() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.archive_comment = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_stored_entries(&[rar50::EncryptedStoredEntry {
                name: b"rar5-header-comment-secret.txt",
                data: b"facade rar5 header encrypted comment payload\n",
                mtime: Some(0),
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }])
            .encrypted_archive_comment(Some(rar50::EncryptedArchiveCommentEntry {
                data: b"facade header encrypted comment\n",
                password: b"password",
            }))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let comment = raw.services().next().unwrap().extract(raw).unwrap();
        assert_eq!(comment.data, b"facade header encrypted comment\n");
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 header encrypted comment payload\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar50_header_encrypted_compressed_archive_with_comment() {
        let payload = b"facade rar5 header encrypted compressed comment payload\n".repeat(8);
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.archive_comment = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_compressed_entries(&[rar50::EncryptedCompressedEntry {
                name: b"rar5-header-compressed-comment-secret.txt",
                data: &payload,
                mtime: Some(0),
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }])
            .encrypted_archive_comment(Some(rar50::EncryptedArchiveCommentEntry {
                data: b"facade header encrypted compressed comment\n",
                password: b"password",
            }))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let comment = raw.services().next().unwrap().extract(raw).unwrap();
        assert_eq!(
            comment.data,
            b"facade header encrypted compressed comment\n"
        );
        let extracted = archive.extract(Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_encrypted_stored_archive_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.recovery_record = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_stored_entries(&[rar50::EncryptedStoredEntry {
                name: b"rar5-encrypted-recovery.txt",
                data: b"facade rar5 encrypted recovery payload\n",
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }])
            .recovery_percent(Some(6))
            .recovery_password(Some(b"password"))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.has_recovery_record());
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"RR");
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 6);
        let recovery_data = service.extract(raw).unwrap().data;
        assert!(recovery_data.starts_with(b"{RB}"));
        assert_eq!(
            u32::from_le_bytes(recovery_data[0x0c..0x10].try_into().unwrap()) as usize,
            recovery_data.len()
        );
        let extracted = archive.extract(None).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 encrypted recovery payload\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar50_encrypted_compressed_archive_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.recovery_record = true;
        let payload = b"facade rar5 encrypted compressed recovery payload repeated\n".repeat(8);
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_compressed_entries(&[rar50::EncryptedCompressedEntry {
                name: b"rar5-encrypted-compressed-recovery.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }])
            .recovery_percent(Some(6))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.has_recovery_record());
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"RR");
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 6);
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_header_encrypted_stored_archive_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.recovery_record = true;
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_stored_entries(&[rar50::EncryptedStoredEntry {
                name: b"rar5-header-recovery.txt",
                data: b"facade rar5 header encrypted recovery payload\n",
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }])
            .recovery_percent(Some(4))
            .recovery_password(Some(b"password"))
            .finish()
            .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.has_recovery_record());
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"RR");
        assert!(!service.encrypted);
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 4);
        let recovery_data = service.extract(raw).unwrap().data;
        assert!(recovery_data.starts_with(b"{RB}"));
        assert_eq!(
            u32::from_le_bytes(recovery_data[0x0c..0x10].try_into().unwrap()) as usize,
            recovery_data.len()
        );
        let extracted = archive.extract(None).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 header encrypted recovery payload\n"
        );
    }

    #[test]
    fn archive_writer_creates_rar50_header_encrypted_compressed_archive_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.recovery_record = true;
        let payload =
            b"facade rar5 header encrypted compressed recovery payload repeated\n".repeat(8);
        let bytes = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_writer()
            .unwrap()
            .encrypted_compressed_entries(&[rar50::EncryptedCompressedEntry {
                name: b"rar5-header-compressed-recovery.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }])
            .recovery_percent(Some(4))
            .finish()
            .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.has_recovery_record());
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"RR");
        assert!(!service.encrypted);
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 4);
        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_encrypted_stored_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let payload = b"facade rar5 encrypted split payload\n".repeat(12);
        let parts = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_options()
            .map(rar50::Rar50VolumeWriter::new)
            .unwrap()
            .encrypted_stored_entry(rar50::EncryptedStoredEntry {
                name: b"split-secret50.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            })
            .max_payload_per_volume(16)
            .finish()
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();

        let extracted = rar50::extract_volumes_with_password(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-secret50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_encrypted_stored_volumes_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.recovery_record = true;
        let payload = b"facade rar5 encrypted recovery split payload\n".repeat(12);
        let parts = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_options()
            .map(rar50::Rar50VolumeWriter::new)
            .unwrap()
            .encrypted_stored_entry(rar50::EncryptedStoredEntry {
                name: b"split-secret50-rr.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            })
            .max_payload_per_volume(16)
            .recovery_percent(Some(8))
            .finish()
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();
        assert_rar50_volume_recovery_records(&archives, 8);

        let extracted = rar50::extract_volumes_with_password(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-secret50-rr.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_header_encrypted_stored_volumes_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.recovery_record = true;
        let payload = b"facade rar5 header encrypted recovery split payload\n".repeat(4);
        let parts = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_options()
            .map(rar50::Rar50VolumeWriter::new)
            .unwrap()
            .encrypted_stored_entry(rar50::EncryptedStoredEntry {
                name: b"split-header-secret50-rr.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            })
            .max_payload_per_volume(16)
            .recovery_percent(Some(8))
            .finish()
            .unwrap();
        assert!(matches!(
            rar50::Archive::parse(&parts[0]),
            Err(Error::NeedPassword)
        ));
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();
        assert_rar50_volume_recovery_records(&archives, 8);

        let extracted = rar50::extract_volumes_with_password(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-header-secret50-rr.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_header_encrypted_stored_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let payload = b"facade rar5 header encrypted split payload\n".repeat(12);
        let parts = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_options()
            .map(rar50::Rar50VolumeWriter::new)
            .unwrap()
            .encrypted_stored_entry(rar50::EncryptedStoredEntry {
                name: b"split-header-secret50.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            })
            .max_payload_per_volume(16)
            .finish()
            .unwrap();
        assert!(matches!(
            rar50::Archive::parse(&parts[0]),
            Err(Error::NeedPassword)
        ));
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();

        let extracted = rar50::extract_volumes_with_password(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-header-secret50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_encrypted_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let payload = b"facade rar5 encrypted compressed split payload\n".repeat(12);
        let parts = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_options()
            .map(rar50::Rar50VolumeWriter::new)
            .unwrap()
            .encrypted_compressed_entries(std::slice::from_ref(&rar50::EncryptedCompressedEntry {
                name: b"split-secret-compressed50.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }))
            .max_payload_per_volume(32)
            .finish()
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();

        let extracted = rar50::extract_volumes_with_password(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-secret-compressed50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_encrypted_compressed_volumes_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.recovery_record = true;
        let payload = b"facade rar5 encrypted compressed recovery split payload\n".repeat(12);
        let entries = [rar50::EncryptedCompressedEntry {
            name: b"split-secret-compressed50-rr.txt",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        }];
        let parts = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_options()
            .map(rar50::Rar50VolumeWriter::new)
            .unwrap()
            .encrypted_compressed_entries(&entries)
            .max_payload_per_volume(32)
            .recovery_percent(Some(8))
            .finish()
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();
        assert_rar50_volume_recovery_records(&archives, 8);

        let extracted = rar50::extract_volumes_with_password(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-secret-compressed50-rr.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_header_encrypted_compressed_volumes_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.recovery_record = true;
        let payload =
            b"facade rar5 header encrypted compressed recovery split payload\n".repeat(12);
        let entries = [rar50::EncryptedCompressedEntry {
            name: b"split-header-secret-compressed50-rr.txt",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        }];
        let parts = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_options()
            .map(rar50::Rar50VolumeWriter::new)
            .unwrap()
            .encrypted_compressed_entries(&entries)
            .max_payload_per_volume(32)
            .recovery_percent(Some(8))
            .finish()
            .unwrap();
        assert!(matches!(
            rar50::Archive::parse(&parts[0]),
            Err(Error::NeedPassword)
        ));
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();
        assert_rar50_volume_recovery_records(&archives, 8);

        let extracted = rar50::extract_volumes_with_password(&archives, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].name,
            b"split-header-secret-compressed50-rr.txt"
        );
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_encrypted_solid_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.solid = true;
        let payload = b"facade rar5 encrypted solid compressed split payload\n".repeat(12);
        let parts = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_options()
            .map(rar50::Rar50VolumeWriter::new)
            .unwrap()
            .encrypted_compressed_entries(std::slice::from_ref(&rar50::EncryptedCompressedEntry {
                name: b"split-solid-secret-compressed50.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }))
            .max_payload_per_volume(32)
            .finish()
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        assert!(archives.iter().all(|archive| archive.main.is_solid()));

        let extracted = rar50::extract_volumes_with_password(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-solid-secret-compressed50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_header_encrypted_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        let payload: Vec<u8> = (0..512).map(|index| (index * 37 + 11) as u8).collect();
        let parts = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_options()
            .map(rar50::Rar50VolumeWriter::new)
            .unwrap()
            .encrypted_compressed_entries(std::slice::from_ref(&rar50::EncryptedCompressedEntry {
                name: b"split-header-secret-compressed50.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }))
            .max_payload_per_volume(64)
            .finish()
            .unwrap();
        assert!(matches!(
            rar50::Archive::parse(&parts[0]),
            Err(Error::NeedPassword)
        ));
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();

        let extracted = rar50::extract_volumes(&archives).unwrap();
        assert_eq!(extracted[0].name, b"split-header-secret-compressed50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_header_encrypted_solid_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        features.header_encryption = true;
        features.solid = true;
        let payload = b"facade rar5 header encrypted solid compressed split payload\n".repeat(12);
        let parts = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_options()
            .map(rar50::Rar50VolumeWriter::new)
            .unwrap()
            .encrypted_compressed_entries(std::slice::from_ref(&rar50::EncryptedCompressedEntry {
                name: b"split-header-solid-secret-compressed50.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
                password: b"password",
            }))
            .max_payload_per_volume(32)
            .finish()
            .unwrap();
        assert!(matches!(
            rar50::Archive::parse(&parts[0]),
            Err(Error::NeedPassword)
        ));
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();
        assert!(archives.iter().all(|archive| archive.main.is_solid()));

        let extracted = rar50::extract_volumes(&archives).unwrap();
        assert_eq!(
            extracted[0].name,
            b"split-header-solid-secret-compressed50.txt"
        );
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_stored_volumes() {
        let payload = b"facade rar5 stored split payload\n".repeat(20);
        let parts = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .rar50_options()
            .map(rar50::Rar50VolumeWriter::new)
            .unwrap()
            .stored_entry(rar50::StoredEntry {
                name: b"split50.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            })
            .max_payload_per_volume(80)
            .finish()
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        let extracted = rar50::extract_volumes(&archives).unwrap();

        assert_eq!(extracted[0].name, b"split50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_stored_volumes_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.recovery_record = true;
        let payload = b"facade rar5 stored recovery split payload\n".repeat(20);
        let parts = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_options()
            .map(rar50::Rar50VolumeWriter::new)
            .unwrap()
            .stored_entry(rar50::StoredEntry {
                name: b"split50-rr.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            })
            .max_payload_per_volume(80)
            .recovery_percent(Some(8))
            .finish()
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        assert_rar50_volume_recovery_records(&archives, 8);
        let extracted = rar50::extract_volumes(&archives).unwrap();

        assert_eq!(extracted[0].name, b"split50-rr.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_compressed_volumes() {
        let payload: Vec<u8> = (0..512).map(|index| (index * 53 + 17) as u8).collect();
        let parts = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .rar50_options()
            .map(rar50::Rar50VolumeWriter::new)
            .unwrap()
            .compressed_entries(std::slice::from_ref(&rar50::CompressedEntry {
                name: b"split-compressed50.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            }))
            .max_payload_per_volume(64)
            .finish()
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        let extracted = rar50::extract_volumes(&archives).unwrap();

        assert_eq!(extracted[0].name, b"split-compressed50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_compressed_volumes_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.recovery_record = true;
        let payload: Vec<u8> = (0..512).map(|index| (index * 53 + 17) as u8).collect();
        let entries = [rar50::CompressedEntry {
            name: b"split-compressed50-rr.txt",
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }];
        let parts = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_options()
            .map(rar50::Rar50VolumeWriter::new)
            .unwrap()
            .compressed_entries(&entries)
            .max_payload_per_volume(64)
            .recovery_percent(Some(8))
            .finish()
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        assert_rar50_volume_recovery_records(&archives, 8);
        let extracted = rar50::extract_volumes(&archives).unwrap();

        assert_eq!(extracted[0].name, b"split-compressed50-rr.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_solid_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let payload = b"facade rar5 solid compressed split payload\n".repeat(12);
        let parts = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_options()
            .map(rar50::Rar50VolumeWriter::new)
            .unwrap()
            .compressed_entries(std::slice::from_ref(&rar50::CompressedEntry {
                name: b"split-solid-compressed50.txt",
                data: &payload,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            }))
            .max_payload_per_volume(32)
            .finish()
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        assert!(archives.iter().all(|archive| archive.main.is_solid()));
        let extracted = rar50::extract_volumes(&archives).unwrap();

        assert_eq!(extracted[0].name, b"split-solid-compressed50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn archive_writer_creates_rar50_multi_file_solid_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let first = b"facade rar5 multi-file solid split shared phrase\n".repeat(12);
        let second = b"facade rar5 multi-file solid split shared phrase\nsecond\n".repeat(10);
        let entries = [
            rar50::CompressedEntry {
                name: b"solid-volume-one.txt",
                data: &first,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            },
            rar50::CompressedEntry {
                name: b"solid-volume-two.txt",
                data: &second,
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            },
        ];
        let parts = ArchiveWriter::new(ArchiveVersion::Rar50)
            .unwrap()
            .with_features(features)
            .rar50_options()
            .map(rar50::Rar50VolumeWriter::new)
            .unwrap()
            .compressed_entries(&entries)
            .max_payload_per_volume(96)
            .finish()
            .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        assert!(archives.iter().all(|archive| archive.main.is_solid()));
        let extracted = rar50::extract_volumes(&archives).unwrap();

        assert_eq!(extracted[0].name, b"solid-volume-one.txt");
        assert_eq!(extracted[0].data, first);
        assert_eq!(extracted[1].name, b"solid-volume-two.txt");
        assert_eq!(extracted[1].data, second);
    }
}
