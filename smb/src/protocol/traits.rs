use nom::error::ErrorKind;

use crate::util::error::SMBError;

pub trait SMBFromBytes {
    fn parse_smb_message(input: &[u8]) -> Result<Self, SMBError> where Self: Sized;
}

pub trait SMBToBytes {
    fn smb_to_bytes();
}

impl SMBFromBytes for u8 {
    fn parse_smb_message(input: &[u8]) -> Result<Self, SMBError> {
        Ok(input[0])
    }
}

impl SMBFromBytes for u16 {
    fn parse_smb_message(input: &[u8]) -> Result<Self, SMBError> {
        let slice = <([u8; 2])>::try_from(&input[0..2])
            .map_err(|_e| SMBError::ParseError(ErrorKind::Fail));
        Ok(Self::from_be_bytes(slice?))
    }
}

impl SMBFromBytes for u32 {
    fn parse_smb_message(input: &[u8]) -> Result<Self, SMBError> {
        let slice = <([u8; 4])>::try_from(&input[0..4])
            .map_err(|_e| SMBError::ParseError(ErrorKind::Fail));
        Ok(Self::from_be_bytes(slice?))
    }
}

impl SMBFromBytes for u64 {
    fn parse_smb_message(input: &[u8]) -> Result<Self, SMBError> {
        let slice = <([u8; 8])>::try_from(&input[0..8])
            .map_err(|_e| SMBError::ParseError(ErrorKind::Fail));
        Ok(Self::from_be_bytes(slice?))
    }
}