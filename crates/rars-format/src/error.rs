use crate::version::ArchiveVersion;

pub type Result<T> = std::result::Result<T, Error>;

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
    UnsupportedCompression {
        family: &'static str,
        unpack_version: u8,
        method: u8,
    },
    UnsupportedEncryption {
        family: &'static str,
        unpack_version: u8,
    },
    Io(String),
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
            Self::Io(message) => write!(f, "I/O error: {message}"),
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
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AtArchiveOffset { source, .. } | Self::AtEntry { source, .. } => Some(source),
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
        match error {
            rars_codec::Error::InvalidData(message) => Self::InvalidHeader(message),
            rars_codec::Error::NeedMoreInput => Self::InvalidHeader("codec input is truncated"),
            _ => Self::InvalidHeader("codec error"),
        }
    }
}

impl From<rars_recovery::rar5::Error> for Error {
    fn from(error: rars_recovery::rar5::Error) -> Self {
        match error {
            rars_recovery::rar5::Error::BadRecoveryChunk => {
                Self::InvalidHeader("RAR 5 recovery chunk is invalid")
            }
            rars_recovery::rar5::Error::OddShardSize => {
                Self::InvalidHeader("RAR 5 recovery shard size is odd")
            }
            rars_recovery::rar5::Error::PlanOverflow => {
                Self::InvalidHeader("RAR 5 recovery plan overflows")
            }
            rars_recovery::rar5::Error::PrefixExceedsPlan => {
                Self::InvalidHeader("RAR 5 recovery prefix exceeds planned shard capacity")
            }
            rars_recovery::rar5::Error::TooManyDamagedShards => {
                Self::InvalidHeader("RAR 5 recovery data cannot repair this many damaged shards")
            }
            rars_recovery::rar5::Error::ShardSizeMismatch => {
                Self::InvalidHeader("RAR 5 recovery shard sizes differ")
            }
            rars_recovery::rar5::Error::TooManyShards => {
                Self::InvalidHeader("RAR 5 recovery shard count is invalid")
            }
            rars_recovery::rar5::Error::SingularElement => {
                Self::InvalidHeader("RAR 5 recovery matrix is singular")
            }
            _ => Self::InvalidHeader("RAR 5 recovery error"),
        }
    }
}

impl From<rars_recovery::rar3::Error> for Error {
    fn from(error: rars_recovery::rar3::Error) -> Self {
        match error {
            rars_recovery::rar3::Error::InvalidParitySize => {
                Self::InvalidHeader("RAR 3 recovery parity size is invalid")
            }
            rars_recovery::rar3::Error::InvalidCodewordSize => {
                Self::InvalidHeader("RAR 3 recovery codeword size is invalid")
            }
            rars_recovery::rar3::Error::TooManyErasures => {
                Self::InvalidHeader("RAR 3 recovery data cannot repair this many erasures")
            }
            rars_recovery::rar3::Error::DecodeFailed => {
                Self::InvalidHeader("RAR 3 recovery decode failed")
            }
            _ => Self::InvalidHeader("RAR 3 recovery error"),
        }
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
}
