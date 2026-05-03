mod ppmd;
pub mod rar13;
pub mod rar20;
pub mod rar29;
pub mod rar50;
pub mod rarvm;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidData(&'static str),
    NeedMoreInput,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidData(msg) => write!(f, "{msg}"),
            Self::NeedMoreInput => write!(f, "more input is required"),
        }
    }
}

impl std::error::Error for Error {}
