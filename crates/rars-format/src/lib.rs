pub mod detect;
pub mod error;
pub mod features;
pub mod rar13;
pub mod version;

pub use detect::{detect_archive_family, find_archive_start, ArchiveSignature};
pub use error::{Error, Result};
pub use features::FeatureSet;
pub use version::{ArchiveFamily, ArchiveVersion};
