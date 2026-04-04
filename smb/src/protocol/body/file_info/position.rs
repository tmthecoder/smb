use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

/// FILE_POSITION_INFORMATION (MS-FSCC 2.4.35) — 8 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FilePositionInformation {
    #[smb_direct(start(fixed = 0))]
    current_byte_offset: u64,
}

impl FilePositionInformation {
    pub fn new(current_byte_offset: u64) -> Self {
        Self { current_byte_offset }
    }

    pub fn current_byte_offset(&self) -> u64 { self.current_byte_offset }
}
