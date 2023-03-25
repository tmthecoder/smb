use error::SMBError;

pub mod error;

pub type SMBResult<I, O, E> = Result<(I, O), E>;

pub trait SMBFromBytes {
    fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> where Self: Sized;
}

pub trait SMBToBytes {
    fn smb_to_bytes();
}

impl SMBFromBytes for u8 {
    fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> {
        Ok((&input[0..], input[0]))
    }
}

impl SMBFromBytes for u16 {
    fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> {
        if input.len() < 2 {
            return Err(SMBError::ParseError("Slice is too short".into()));
        }
        let slice = <([u8; 2])>::try_from(&input[0..2])
            .map_err(|_e| SMBError::ParseError("Invalid byte slice".into()));
        Ok((&input[2..], Self::from_le_bytes(slice?)))
    }
}

impl SMBFromBytes for u32 {
    fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> {
        if input.len() < 4 {
            return Err(SMBError::ParseError("Slice is too short".into()));
        }
        let slice = <([u8; 4])>::try_from(&input[0..4])
            .map_err(|_e| SMBError::ParseError("Invalid byte slice".into()));
        Ok((&input[4..], Self::from_le_bytes(slice?)))
    }
}

impl SMBFromBytes for u64 {
    fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> {
        if input.len() < 8 {
            return Err(SMBError::ParseError("Slice is too short".into()));
        }
        let slice = <([u8; 8])>::try_from(&input[0..8])
            .map_err(|_e| SMBError::ParseError("Invalid byte slice".into()));
        Ok((&input[8..], Self::from_le_bytes(slice?)))
    }
}

impl SMBFromBytes for [u8; 16] {
    fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> {
        if input.len() < 16 {
            return Err(SMBError::ParseError("Slice is too short".into()));
        }
        let res = <([u8; 16])>::try_from(&input[0..16])
            .map_err(|_e| SMBError::ParseError("Invalid byte slice".into()))?;
        Ok((&input[16..], res))
    }
}