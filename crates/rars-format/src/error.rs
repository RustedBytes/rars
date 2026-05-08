use crate::version::{ArchiveFamily, ArchiveVersion};
use std::sync::Arc;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct IoError {
    pub kind: std::io::ErrorKind,
    pub message: String,
    source: Arc<std::io::Error>,
}

impl IoError {
    pub fn source(&self) -> &(dyn std::error::Error + 'static) {
        self.source.as_ref()
    }
}

impl PartialEq for IoError {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.message == other.message
    }
}

impl Eq for IoError {}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    TooShort,
    UnsupportedSignature,
    InvalidHeader(&'static str),
    AtArchiveOffset {
        offset: usize,
        source: Box<Error>,
    },
    AtEntry {
        name: Vec<u8>,
        operation: &'static str,
        source: Box<Error>,
    },
    UnsupportedVersion(ArchiveVersion),
    UnsupportedFeature {
        version: ArchiveVersion,
        feature: &'static str,
    },
    UnsupportedFamilyFeature {
        family: ArchiveFamily,
        feature: &'static str,
    },
    UnsupportedCompression {
        family: &'static str,
        unpack_version: u8,
        method: u8,
    },
    UnsupportedEncryption {
        family: &'static str,
        unpack_version: u8,
    },
    Io(IoError),
    NeedPassword,
    WrongPasswordOrCorruptData,
    CrcMismatch {
        expected: u16,
        actual: u16,
    },
    Crc32Mismatch {
        expected: u32,
        actual: u32,
    },
    HashMismatch {
        hash_type: u64,
    },
    Codec(rars_codec::Error),
    Rar3Recovery(rars_recovery::rar3::Error),
    Rar5Recovery(rars_recovery::rar5::Error),
    Rar50Crypto(rars_crypto::rar50::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "input is too short"),
            Self::UnsupportedSignature => write!(f, "unsupported archive signature"),
            Self::InvalidHeader(msg) => write!(f, "invalid header: {msg}"),
            Self::AtArchiveOffset { offset, source } => {
                write!(f, "at archive offset {offset:#x}: {source}")
            }
            Self::AtEntry {
                name,
                operation,
                source,
            } => {
                write!(
                    f,
                    "while {operation} entry '{}': {source}",
                    String::from_utf8_lossy(name)
                )
            }
            Self::UnsupportedVersion(version) => write!(f, "unsupported version: {version:?}"),
            Self::UnsupportedFeature { version, feature } => {
                write!(f, "feature {feature} is not supported by {version:?}")
            }
            Self::UnsupportedFamilyFeature { family, feature } => {
                write!(f, "feature {feature} is not supported by {family:?}")
            }
            Self::UnsupportedCompression {
                family,
                unpack_version,
                method,
            } => write!(
                f,
                "{family} compression is not supported: unpack version {unpack_version}, method {method:#04x}"
            ),
            Self::UnsupportedEncryption {
                family,
                unpack_version,
            } => write!(
                f,
                "{family} encryption is not supported: unpack version {unpack_version}"
            ),
            Self::Io(error) => write!(f, "I/O error: {}", error.message),
            Self::NeedPassword => write!(f, "a password is required"),
            Self::WrongPasswordOrCorruptData => {
                write!(f, "wrong password or corrupt encrypted data")
            }
            Self::CrcMismatch { expected, actual } => {
                write!(
                    f,
                    "checksum mismatch: expected {expected:#06x}, got {actual:#06x}"
                )
            }
            Self::Crc32Mismatch { expected, actual } => {
                write!(
                    f,
                    "checksum mismatch: expected {expected:#010x}, got {actual:#010x}"
                )
            }
            Self::HashMismatch { hash_type } => {
                write!(f, "hash mismatch for hash type {hash_type}")
            }
            Self::Codec(error) => write!(f, "{}", display_codec_error(error)),
            Self::Rar3Recovery(error) => write!(f, "{}", display_rar3_recovery_error(error)),
            Self::Rar5Recovery(error) => write!(f, "{}", display_rar5_recovery_error(error)),
            Self::Rar50Crypto(error) => write!(f, "{}", display_rar50_crypto_error(error)),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(IoError {
            kind: error.kind(),
            message: error.to_string(),
            source: Arc::new(error),
        })
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AtArchiveOffset { source, .. } | Self::AtEntry { source, .. } => Some(source),
            Self::Codec(source) => Some(source),
            Self::Io(source) => Some(source.source()),
            _ => None,
        }
    }
}

impl Error {
    pub fn at_archive_offset(self, offset: usize) -> Self {
        Self::AtArchiveOffset {
            offset,
            source: Box::new(self),
        }
    }

    pub fn at_entry(self, name: Vec<u8>, operation: &'static str) -> Self {
        Self::AtEntry {
            name,
            operation,
            source: Box::new(self),
        }
    }
}

impl From<rars_codec::Error> for Error {
    fn from(error: rars_codec::Error) -> Self {
        Self::Codec(error)
    }
}

impl From<rars_recovery::rar5::Error> for Error {
    fn from(error: rars_recovery::rar5::Error) -> Self {
        Self::Rar5Recovery(error)
    }
}

impl From<rars_recovery::rar3::Error> for Error {
    fn from(error: rars_recovery::rar3::Error) -> Self {
        Self::Rar3Recovery(error)
    }
}

impl From<rars_crypto::rar50::Error> for Error {
    fn from(error: rars_crypto::rar50::Error) -> Self {
        Self::Rar50Crypto(error)
    }
}

fn display_codec_error(error: &rars_codec::Error) -> &'static str {
    match error {
        rars_codec::Error::InvalidData(message) => message,
        rars_codec::Error::NeedMoreInput => "codec input is truncated",
        _ => "codec error",
    }
}

fn display_rar5_recovery_error(error: &rars_recovery::rar5::Error) -> &'static str {
    match error {
        rars_recovery::rar5::Error::BadRecoveryChunk => "RAR 5 recovery chunk is invalid",
        rars_recovery::rar5::Error::OddShardSize => "RAR 5 recovery shard size is odd",
        rars_recovery::rar5::Error::PlanOverflow => "RAR 5 recovery plan overflows",
        rars_recovery::rar5::Error::PrefixExceedsPlan => {
            "RAR 5 recovery prefix exceeds planned shard capacity"
        }
        rars_recovery::rar5::Error::TooManyDamagedShards => {
            "RAR 5 recovery data cannot repair this many damaged shards"
        }
        rars_recovery::rar5::Error::ShardSizeMismatch => "RAR 5 recovery shard sizes differ",
        rars_recovery::rar5::Error::TooManyShards => "RAR 5 recovery shard count is invalid",
        rars_recovery::rar5::Error::SingularElement => "RAR 5 recovery matrix is singular",
        _ => "RAR 5 recovery error",
    }
}

fn display_rar3_recovery_error(error: &rars_recovery::rar3::Error) -> &'static str {
    match error {
        rars_recovery::rar3::Error::InvalidParitySize => "RAR 3 recovery parity size is invalid",
        rars_recovery::rar3::Error::InvalidCodewordSize => {
            "RAR 3 recovery codeword size is invalid"
        }
        rars_recovery::rar3::Error::TooManyErasures => {
            "RAR 3 recovery data cannot repair this many erasures"
        }
        rars_recovery::rar3::Error::DecodeFailed => "RAR 3 recovery decode failed",
        _ => "RAR 3 recovery error",
    }
}

fn display_rar50_crypto_error(error: &rars_crypto::rar50::Error) -> &'static str {
    match error {
        rars_crypto::rar50::Error::KdfCountTooLarge => "RAR 5 KDF count is too large",
        rars_crypto::rar50::Error::BadPassword => "wrong password or corrupt encrypted data",
        rars_crypto::rar50::Error::UnalignedInput => "RAR 5 AES input is not block aligned",
        _ => "RAR 5 crypto error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_offset_context_exposes_source_error() {
        let error = Error::InvalidHeader("bad block").at_archive_offset(0x1234);

        assert_eq!(
            error.to_string(),
            "at archive offset 0x1234: invalid header: bad block"
        );
        assert_eq!(
            std::error::Error::source(&error).map(ToString::to_string),
            Some("invalid header: bad block".to_string())
        );
    }

    #[test]
    fn entry_context_exposes_source_error() {
        let error = Error::Crc32Mismatch {
            expected: 1,
            actual: 2,
        }
        .at_entry(b"hello.txt".to_vec(), "verifying");

        assert_eq!(
            error.to_string(),
            "while verifying entry 'hello.txt': checksum mismatch: expected 0x00000001, got 0x00000002"
        );
        assert_eq!(
            std::error::Error::source(&error).map(ToString::to_string),
            Some("checksum mismatch: expected 0x00000001, got 0x00000002".to_string())
        );
    }

    #[test]
    fn io_error_preserves_error_kind() {
        let error = Error::from(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "locked",
        ));

        assert!(matches!(
            error,
            Error::Io(ref source) if source.kind == std::io::ErrorKind::PermissionDenied
        ));
        assert_eq!(error.to_string(), "I/O error: locked");
        assert_eq!(
            std::error::Error::source(&error).map(ToString::to_string),
            Some("locked".to_string())
        );
    }

    #[test]
    fn unsupported_codec_errors_are_not_reported_as_invalid_headers() {
        assert_eq!(
            Error::UnsupportedCompression {
                family: "RAR 1.5-4.x",
                unpack_version: 14,
                method: 0x33,
            }
            .to_string(),
            "RAR 1.5-4.x compression is not supported: unpack version 14, method 0x33"
        );
        assert_eq!(
            Error::UnsupportedEncryption {
                family: "RAR 1.5-4.x",
                unpack_version: 14,
            }
            .to_string(),
            "RAR 1.5-4.x encryption is not supported: unpack version 14"
        );
    }

    #[test]
    fn codec_errors_remain_inspectable_without_changing_display_text() {
        let error = Error::from(rars_codec::Error::NeedMoreInput);

        assert!(matches!(
            error,
            Error::Codec(rars_codec::Error::NeedMoreInput)
        ));
        assert_eq!(error.to_string(), "codec input is truncated");
        assert_eq!(
            std::error::Error::source(&error).map(ToString::to_string),
            Some("more input is required".to_string())
        );
    }

    #[test]
    fn recovery_errors_remain_inspectable_without_changing_display_text() {
        let error = Error::from(rars_recovery::rar5::Error::TooManyDamagedShards);

        assert!(matches!(
            error,
            Error::Rar5Recovery(rars_recovery::rar5::Error::TooManyDamagedShards)
        ));
        assert_eq!(
            error.to_string(),
            "RAR 5 recovery data cannot repair this many damaged shards"
        );
    }

    #[test]
    fn simple_display_variants_render_their_messages() {
        assert_eq!(Error::TooShort.to_string(), "input is too short");
        assert_eq!(
            Error::UnsupportedSignature.to_string(),
            "unsupported archive signature"
        );
        assert_eq!(Error::NeedPassword.to_string(), "a password is required");
        assert_eq!(
            Error::WrongPasswordOrCorruptData.to_string(),
            "wrong password or corrupt encrypted data"
        );
        assert_eq!(
            Error::HashMismatch { hash_type: 7 }.to_string(),
            "hash mismatch for hash type 7"
        );
        assert_eq!(
            Error::CrcMismatch {
                expected: 0xabcd,
                actual: 0x1234
            }
            .to_string(),
            "checksum mismatch: expected 0xabcd, got 0x1234"
        );
        assert_eq!(
            Error::UnsupportedVersion(ArchiveVersion::Rar50).to_string(),
            "unsupported version: Rar50"
        );
        assert_eq!(
            Error::UnsupportedFeature {
                version: ArchiveVersion::Rar50,
                feature: "quantum compression",
            }
            .to_string(),
            "feature quantum compression is not supported by Rar50"
        );
    }

    #[test]
    fn rar3_recovery_errors_render_messages_through_from_conversion() {
        assert_eq!(
            Error::from(rars_recovery::rar3::Error::InvalidParitySize).to_string(),
            "RAR 3 recovery parity size is invalid"
        );
        assert_eq!(
            Error::from(rars_recovery::rar3::Error::InvalidCodewordSize).to_string(),
            "RAR 3 recovery codeword size is invalid"
        );
        assert_eq!(
            Error::from(rars_recovery::rar3::Error::TooManyErasures).to_string(),
            "RAR 3 recovery data cannot repair this many erasures"
        );
        assert_eq!(
            Error::from(rars_recovery::rar3::Error::DecodeFailed).to_string(),
            "RAR 3 recovery decode failed"
        );
    }

    #[test]
    fn rar5_recovery_errors_render_messages_for_every_named_variant() {
        let cases = [
            (
                rars_recovery::rar5::Error::BadRecoveryChunk,
                "RAR 5 recovery chunk is invalid",
            ),
            (
                rars_recovery::rar5::Error::OddShardSize,
                "RAR 5 recovery shard size is odd",
            ),
            (
                rars_recovery::rar5::Error::PlanOverflow,
                "RAR 5 recovery plan overflows",
            ),
            (
                rars_recovery::rar5::Error::PrefixExceedsPlan,
                "RAR 5 recovery prefix exceeds planned shard capacity",
            ),
            (
                rars_recovery::rar5::Error::ShardSizeMismatch,
                "RAR 5 recovery shard sizes differ",
            ),
            (
                rars_recovery::rar5::Error::TooManyShards,
                "RAR 5 recovery shard count is invalid",
            ),
            (
                rars_recovery::rar5::Error::SingularElement,
                "RAR 5 recovery matrix is singular",
            ),
        ];
        for (variant, expected) in cases {
            assert_eq!(Error::from(variant).to_string(), expected);
        }
    }

    #[test]
    fn rar50_crypto_errors_render_messages_through_from_conversion() {
        assert_eq!(
            Error::from(rars_crypto::rar50::Error::KdfCountTooLarge).to_string(),
            "RAR 5 KDF count is too large"
        );
        assert_eq!(
            Error::from(rars_crypto::rar50::Error::BadPassword).to_string(),
            "wrong password or corrupt encrypted data"
        );
    }

    #[test]
    fn codec_invalid_data_display_uses_inner_message() {
        assert_eq!(
            Error::from(rars_codec::Error::InvalidData("bad symbol")).to_string(),
            "bad symbol"
        );
    }
}
