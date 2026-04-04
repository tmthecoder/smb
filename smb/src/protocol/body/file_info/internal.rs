use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

/// FILE_INTERNAL_INFORMATION (MS-FSCC 2.4.20) — 8 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileInternalInformation {
    #[smb_direct(start(fixed = 0))]
    index_number: u64,
}

impl FileInternalInformation {
    pub fn new(index_number: u64) -> Self {
        Self { index_number }
    }

    pub fn index_number(&self) -> u64 { self.index_number }
}
