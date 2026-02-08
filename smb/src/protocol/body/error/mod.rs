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

