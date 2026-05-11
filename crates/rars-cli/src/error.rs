use std::error::Error as StdError;
use std::num::ParseIntError;
use std::string::FromUtf8Error;

pub(crate) type CliResult<T> = std::result::Result<T, CliError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliErrorClass {
    General,
    Usage,
    Password,
}

#[derive(Debug)]
pub(crate) struct CliError {
    class: CliErrorClass,
    message: String,
}

impl CliError {
    pub(crate) fn general(message: impl Into<String>) -> Self {
        Self {
            class: CliErrorClass::General,
            message: message.into(),
        }
    }

    pub(crate) fn usage(message: impl Into<String>) -> Self {
        Self {
            class: CliErrorClass::Usage,
            message: message.into(),
        }
    }

    pub(crate) fn password(message: impl Into<String>) -> Self {
        Self {
            class: CliErrorClass::Password,
            message: message.into(),
        }
    }

    pub(crate) fn exit_code(&self) -> i32 {
        match self.class {
            CliErrorClass::General => 1,
            CliErrorClass::Usage => 2,
            CliErrorClass::Password => 3,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl StdError for CliError {}

impl From<&str> for CliError {
    fn from(message: &str) -> Self {
        Self::general(message)
    }
}

impl From<String> for CliError {
    fn from(message: String) -> Self {
        Self::general(message)
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self::general(error.to_string())
    }
}

impl From<ParseIntError> for CliError {
    fn from(error: ParseIntError) -> Self {
        Self::usage(error.to_string())
    }
}

impl From<FromUtf8Error> for CliError {
    fn from(error: FromUtf8Error) -> Self {
        Self::general(error.to_string())
    }
}
