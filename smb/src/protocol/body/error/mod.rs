use serde::{Deserialize, Serialize};

use smb_core::nt_status::NTStatus;
use smb_core::{SMBByteSize, SMBToBytes};

/// SMB2 ERROR Response (MS-SMB2 2.2.2)
/// StructureSize (2 bytes) = 9
/// ErrorContextCount (1 byte) = 0
/// Reserved (1 byte) = 0
/// ByteCount (4 bytes) = 0
/// ErrorData (1 byte) = 0 (padding)
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct SMBErrorResponse {
    status: NTStatus,
}

impl SMBErrorResponse {
    pub fn new(status: NTStatus) -> Self {
        Self { status }
    }

    pub fn status(&self) -> NTStatus {
        self.status
    }
}

impl SMBByteSize for SMBErrorResponse {
    fn smb_byte_size(&self) -> usize {
        9
    }
}

impl SMBToBytes for SMBErrorResponse {
    fn smb_to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(9);
        // StructureSize = 9
        bytes.extend_from_slice(&9u16.to_le_bytes());
        // ErrorContextCount = 0
        bytes.push(0);
        // Reserved = 0
        bytes.push(0);
        // ByteCount = 0
        bytes.extend_from_slice(&0u32.to_le_bytes());
        // ErrorData padding byte
        bytes.push(0);
        bytes
    }
}

impl smb_core::SMBFromBytes for SMBErrorResponse {
    fn smb_from_bytes(input: &[u8]) -> smb_core::SMBParseResult<&[u8], Self> where Self: Sized {
        if input.len() < 9 {
            return Err(smb_core::error::SMBError::parse_error("Error response too small"));
        }
        Ok((&input[9..], Self { status: NTStatus::UnknownError }))
    }
}