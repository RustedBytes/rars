pub use rars_format::{
    detect_archive_family, find_archive_start, rar13, ArchiveFamily, ArchiveSignature,
    ArchiveVersion, Error, FeatureSet, Result,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Archive {
    Rar13(rar13::Archive),
}

impl Archive {
    pub fn family(&self) -> ArchiveFamily {
        match self {
            Self::Rar13(_) => ArchiveFamily::Rar13,
        }
    }

    pub fn extract(&self, password: Option<&[u8]>) -> Result<Vec<rar13::ExtractedEntry>> {
        match self {
            Self::Rar13(archive) => archive.extract(password),
        }
    }

    pub fn as_rar13(&self) -> Option<&rar13::Archive> {
        match self {
            Self::Rar13(archive) => Some(archive),
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
            ArchiveFamily::Rar15To40 => Err(Error::UnsupportedVersion(ArchiveVersion::Rar15)),
            ArchiveFamily::Rar50Plus => Err(Error::UnsupportedVersion(ArchiveVersion::Rar50)),
        }
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
