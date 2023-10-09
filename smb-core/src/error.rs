use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum SMBError<'a> {
    ParseError(&'a str),
    CryptoError(&'a str),
    PreconditionFailed(&'a str),
}

impl Display for SMBError<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError(x) => write!(f, "Parse Error with kind: {}", x),
            Self::CryptoError(x) => write!(f, "Crypto operation failed: {}", x),
            Self::PreconditionFailed(x) => write!(f, "Precondition failed: {}", x),
        }
    }
}

impl std::error::Error for SMBError<'_> {}