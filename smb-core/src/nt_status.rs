use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use crate::{SMBByteSize, SMBFromBytes, SMBParseResult, SMBToBytes};
use crate::error::SMBError;

#[repr(u32)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TryFromPrimitive, Copy)]
pub enum NTStatus {
    StatusSuccess = 0x0,
    MoreProcessingRequired = 0xC0000016,
    SecIContinueNeeded = 0x00090312,
    InvalidParameter = 0xC000000D,
    AccessDenied = 0xC0000022,
    StatusLogonFailure = 0xC000006D,
    StatusNotSupported = 0xC00000BB,
    BadNetworkName = 0xC00000CC,
    RequestNotAccepted = 0xC00000D0,
    UserSessionDeleted = 0xC0000203,
    NetworkSessionExpired = 0xC000035C,
    UnknownError = 0xFFFFFFFF,
}

impl SMBByteSize for NTStatus {
    fn smb_byte_size(&self) -> usize {
        std::mem::size_of_val(&(*self as u32))
    }
}

impl SMBFromBytes for NTStatus {
    fn smb_from_bytes(input: &[u8]) -> SMBParseResult<&[u8], Self> where Self: Sized {
        u32::smb_from_bytes(input)
            .map(|(remaining, underlying)| {
                let res = Self::try_from_primitive(underlying)
                    .map_err(SMBError::parse_error)?;
                Ok((remaining, res))
            })?
    }
}

impl SMBToBytes for NTStatus {
    fn smb_to_bytes(&self) -> Vec<u8> {
        (*self as u32).smb_to_bytes()
    }
}