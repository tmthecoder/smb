use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum SMBError {
    ParseError(SMBParseError),
    CryptoError(SMBCryptoError),
    PreconditionFailed(SMBPreconditionFailedError),
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

impl Display for SMBError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError(x) => write!(f, "{}", x),
            Self::CryptoError(x) => write!(f, "{}", x),
            Self::PreconditionFailed(x) => write!(f, "{}", x),
        }
    }
}

impl std::error::Error for SMBError {}