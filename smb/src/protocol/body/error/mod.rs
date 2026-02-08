use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

/// SMB2 ERROR Response (MS-SMB2 2.2.2)
/// StructureSize (2 bytes) = 9
/// ErrorContextCount (1 byte) = 0
/// Reserved (1 byte) = 0
/// ByteCount (4 bytes) = 0
/// ErrorData (1 byte) = 0 (padding)
///
/// NTStatus is carried in the SMB2 header (channel_sequence field),
/// not in the error body.
#[derive(
    Debug,
    PartialEq,
    Eq,
    SMBByteSize,
    SMBToBytes,
    SMBFromBytes,
    Serialize,
    Deserialize,
    Clone
)]
#[smb_byte_tag(value = 9)]
pub struct SMBErrorResponse {
    #[smb_skip(start = 2, length = 2)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_skip(start = 4, length = 4)]
    byte_count: PhantomData<Vec<u8>>,
    #[smb_skip(start = 8, length = 1)]
    error_data: PhantomData<Vec<u8>>,
}

impl SMBErrorResponse {
    pub fn new() -> Self {
        Self {
            reserved: PhantomData,
            byte_count: PhantomData,
            error_data: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBFromBytes, SMBToBytes};

    /// MS-SMB2 2.2.2: StructureSize MUST be 9.
    #[test]
    fn error_response_structure_size() {
        let err = SMBErrorResponse::new();
        let bytes = err.smb_to_bytes();
        let structure_size = u16::from_le_bytes([bytes[0], bytes[1]]);
        assert_eq!(structure_size, 9, "Error response StructureSize must be 9");
    }

    #[test]
    fn error_response_is_9_bytes() {
        let err = SMBErrorResponse::new();
        let bytes = err.smb_to_bytes();
        assert_eq!(bytes.len(), 9, "Error response body must be 9 bytes");
    }

    #[test]
    fn error_response_context_count_zero() {
        let err = SMBErrorResponse::new();
        let bytes = err.smb_to_bytes();
        assert_eq!(bytes[2], 0, "ErrorContextCount should be 0");
    }

    #[test]
    fn error_response_byte_count_zero() {
        let err = SMBErrorResponse::new();
        let bytes = err.smb_to_bytes();
        let byte_count = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert_eq!(byte_count, 0, "ByteCount should be 0");
    }

    #[test]
    fn error_response_roundtrip() {
        let err = SMBErrorResponse::new();
        let bytes = err.smb_to_bytes();
        let (remaining, parsed) = SMBErrorResponse::smb_from_bytes(&bytes).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(parsed, err);
    }
}
