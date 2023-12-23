use std::fmt::{Display, Formatter};
use std::io;

#[derive(Debug)]
pub enum SMBError {
    ParseError(SMBParseError),
    CryptoError(SMBCryptoError),
    PreconditionFailed(SMBPreconditionFailedError),
    IOError(SMBIOError),
    ResponseError(SMBResponseError),
}

impl SMBError {
    pub fn parse_error<T: Into<SMBParseError>>(error: T) -> Self {
        Self::ParseError(error.into())
    }

    pub fn crypto_error<T: Into<SMBCryptoError>>(error: T) -> Self {
        Self::CryptoError(error.into())
    }

    pub fn precondition_failed<T: Into<SMBPreconditionFailedError>>(error: T) -> Self {
        Self::PreconditionFailed(error.into())
    }

    pub fn io_error<T: Into<SMBIOError>>(error: T) -> Self {
        Self::IOError(error.into())
    }

    pub fn response_error<T: Into<SMBResponseError>>(error: T) -> Self {
        Self::ResponseError(error.into())
    }
}

#[derive(Debug)]
pub struct SMBParseError {
    message: String,
}

impl<T: Into<String>> From<T> for SMBParseError {
    fn from(value: T) -> Self {
        Self {
            message: value.into()
        }
    }
}

impl Display for SMBParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Parse failed with error: {}", self.message)
    }
}

#[derive(Debug)]
pub struct SMBCryptoError {
    message: String,
}

impl<T: Into<String>> From<T> for SMBCryptoError {
    fn from(value: T) -> Self {
        Self {
            message: value.into()
        }
    }
}

impl Display for SMBCryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Crypto operation failed with error: {}", self.message)
    }
}

#[derive(Debug)]
pub struct SMBPreconditionFailedError {
    message: String,
}

impl<T: Into<String>> From<T> for SMBPreconditionFailedError {
    fn from(value: T) -> Self {
        Self {
            message: value.into()
        }
    }
}

impl Display for SMBPreconditionFailedError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Operation failed with unmet precondition: {}", self.message)
    }
}

#[derive(Debug)]
pub struct SMBIOError {
    error: io::Error,
}

impl<T: Into<io::Error>> From<T> for SMBIOError {
    fn from(value: T) -> Self {
        Self {
            error: value.into()
        }
    }
}

impl Display for SMBIOError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SMB I/O operation failed with error: {}", self.error)
    }
}

#[derive(Debug)]
pub struct SMBResponseError {
    message: String,
}

impl<T: Into<String>> From<T> for SMBResponseError {
    fn from(value: T) -> Self {
        Self {
            message: value.into()
        }
    }
}

impl Display for SMBResponseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SMB response generation failed with: {}", self.message)
    }
}

impl Display for SMBError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError(x) => write!(f, "{}", x),
            Self::CryptoError(x) => write!(f, "{}", x),
            Self::PreconditionFailed(x) => write!(f, "{}", x),
            Self::IOError(x) => write!(f, "{}", x),
            Self::ResponseError(x) => write!(f, "{}", x)
        }
    }
}

impl std::error::Error for SMBError {}