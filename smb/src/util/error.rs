use std::fmt::{Display, format, Formatter, Pointer, write};

use nom::Err;
use nom::error::{Error, ErrorKind};

#[derive(Debug)]
pub enum SMBError {
    ParseError(ErrorKind),
    CryptoError,
    PreconditionFailed(String),
}

impl Display for SMBError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError(x) => write!(f, "Parse Error with kind: {:?}", x),
            Self::CryptoError => write!(f, "Crypto operation failed"),
            Self::PreconditionFailed(x) => write!(f, "Precondition failed: {}", x),
        }
    }
}

impl<I> From<Err<Error<I>>> for SMBError {
    fn from(err: Err<Error<I>>) -> Self {
        match err {
            Err::Error(x) => Self::ParseError(x.code),
            Err::Failure(x) => Self::ParseError(x.code),
            Err::Incomplete(x) => Self::ParseError(ErrorKind::Fail)
        }
    }
}

impl std::error::Error for SMBError {}