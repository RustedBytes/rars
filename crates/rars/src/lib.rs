pub use rars_format::{
    detect_archive_family, find_archive_start, rar13, rar15_40, ArchiveFamily, ArchiveSignature,
    ArchiveVersion, Error, FeatureSet, Result,
};
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Archive {
    Rar13(rar13::Archive),
    Rar15To40(rar15_40::Archive),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedEntry {
    pub name: Vec<u8>,
    pub data: Vec<u8>,
    pub file_time: u32,
    pub file_attr: u32,
    pub is_directory: bool,
}

impl Archive {
    pub fn family(&self) -> ArchiveFamily {
        match self {
            Self::Rar13(_) => ArchiveFamily::Rar13,
            Self::Rar15To40(_) => ArchiveFamily::Rar15To40,
        }
    }

    pub fn extract(&self, password: Option<&[u8]>) -> Result<Vec<ExtractedEntry>> {
        match self {
            Self::Rar13(archive) => archive
                .extract(password)
                .map(|entries| entries.into_iter().map(Into::into).collect()),
            Self::Rar15To40(archive) => archive
                .extract()
                .map(|entries| entries.into_iter().map(Into::into).collect()),
        }
    }

    pub fn as_rar13(&self) -> Option<&rar13::Archive> {
        match self {
            Self::Rar13(archive) => Some(archive),
            Self::Rar15To40(_) => None,
        }
    }

    pub fn as_rar15_40(&self) -> Option<&rar15_40::Archive> {
        match self {
            Self::Rar13(_) => None,
            Self::Rar15To40(archive) => Some(archive),
        }
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

#[derive(Debug, Clone, Copy, Default)]
pub struct ArchiveReader;

impl ArchiveReader {
    pub fn detect(input: &[u8]) -> Result<ArchiveSignature> {
        detect_archive_family(input).ok_or(Error::UnsupportedSignature)
    }

    pub fn read(input: &[u8]) -> Result<Archive> {
        let signature = find_archive_start(input, 128 * 1024).ok_or(Error::UnsupportedSignature)?;
        match signature.family {
            ArchiveFamily::Rar13 => Ok(Archive::Rar13(rar13::Archive::parse(input)?)),
            ArchiveFamily::Rar15To40 => Ok(Archive::Rar15To40(rar15_40::Archive::parse(input)?)),
            ArchiveFamily::Rar50Plus => Err(Error::UnsupportedVersion(ArchiveVersion::Rar50)),
        }
    }

    pub fn read_path(path: impl AsRef<Path>) -> Result<Archive> {
        let path = path.as_ref();
        let mut file = std::fs::File::open(path)?;
        let len = file.metadata()?.len();
        let mut scan = vec![0; len.min(128 * 1024) as usize];
        file.read_exact(&mut scan)?;
        let signature = find_archive_start(&scan, 128 * 1024).ok_or(Error::UnsupportedSignature)?;
        match signature.family {
            ArchiveFamily::Rar13 => Ok(Archive::Rar13(rar13::Archive::parse_path(path)?)),
            ArchiveFamily::Rar15To40 => {
                Ok(Archive::Rar15To40(rar15_40::Archive::parse_path(path)?))
            }
            ArchiveFamily::Rar50Plus => Err(Error::UnsupportedVersion(ArchiveVersion::Rar50)),
        }
    }
}

pub fn extract_volumes(
    archives: &[Archive],
    password: Option<&[u8]>,
) -> Result<Vec<ExtractedEntry>> {
    let Some(first) = archives.first() else {
        return Err(Error::InvalidHeader("volume set is empty"));
    };

    match first.family() {
        ArchiveFamily::Rar13 => {
            let mut typed = Vec::with_capacity(archives.len());
            for archive in archives {
                match archive {
                    Archive::Rar13(archive) => typed.push(archive.clone()),
                    Archive::Rar15To40(_) => {
                        return Err(Error::InvalidHeader("mixed archive families in volume set"));
                    }
                }
            }
            rar13::extract_volumes(&typed, password)
                .map(|entries| entries.into_iter().map(Into::into).collect())
        }
        ArchiveFamily::Rar15To40 => {
            let mut typed = Vec::with_capacity(archives.len());
            for archive in archives {
                match archive {
                    Archive::Rar15To40(archive) => typed.push(archive.clone()),
                    Archive::Rar13(_) => {
                        return Err(Error::InvalidHeader("mixed archive families in volume set"));
                    }
                }
            }
            rar15_40::extract_volumes(&typed)
                .map(|entries| entries.into_iter().map(Into::into).collect())
        }
        ArchiveFamily::Rar50Plus => Err(Error::UnsupportedVersion(ArchiveVersion::Rar50)),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ArchiveWriter {
    options: rar13::WriterOptions,
}

impl ArchiveWriter {
    pub fn new(target: ArchiveVersion) -> Result<Self> {
        if !target.is_rar13_family() {
            return Err(Error::UnsupportedVersion(target));
        }
        Ok(Self {
            options: rar13::WriterOptions {
                target,
                features: FeatureSet::store_only(),
            },
        })
    }

    pub fn with_features(mut self, features: FeatureSet) -> Self {
        self.options.features = features;
        self
    }

    pub fn write_stored(self, entries: &[rar13::StoredEntry<'_>]) -> Result<Vec<u8>> {
        rar13::write_stored_archive(entries, self.options)
    }

    pub fn write_compressed(self, entries: &[rar13::FileEntry<'_>]) -> Result<Vec<u8>> {
        rar13::write_compressed_archive(entries, self.options)
    }
}
