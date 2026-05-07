pub mod detect;
pub mod error;
pub mod features;
pub mod rar13;
pub mod rar15_40;
pub mod rar50;
pub mod version;

mod volume_extract;

pub use detect::{detect_archive_family, find_archive_start, ArchiveSignature};
pub use error::{Error, Result};
pub use features::FeatureSet;
pub use version::{ArchiveFamily, ArchiveVersion};

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ArchiveReadOptions<'a> {
    pub password: Option<&'a [u8]>,
}

impl<'a> ArchiveReadOptions<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_password(password: &'a [u8]) -> Self {
        Self {
            password: Some(password),
        }
    }
}
