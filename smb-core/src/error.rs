use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum SMBError<'a> {
    ParseError(&'a str),
    CryptoError,
    PreconditionFailed(String),
}

impl Display for SMBError<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError(x) => write!(f, "Parse Error with kind: {:?}", x),
            Self::CryptoError => write!(f, "Crypto operation failed"),
            Self::PreconditionFailed(x) => write!(f, "Precondition failed: {}", x),
        }
    }
}

impl std::error::Error for SMBError<'_> {}