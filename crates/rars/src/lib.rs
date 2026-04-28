pub use rars_format::{
    detect_archive_family, find_archive_start, rar13, ArchiveFamily, ArchiveSignature,
    ArchiveVersion, Error, FeatureSet, Result,
};

pub struct ArchiveReader;

impl ArchiveReader {
    pub fn detect(input: &[u8]) -> Result<ArchiveSignature> {
        detect_archive_family(input).ok_or(Error::UnsupportedSignature)
    }
}
