use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

/// FILE_POSITION_INFORMATION (MS-FSCC 2.4.35) — 8 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FilePositionInformation {
    #[smb_direct(start(fixed = 0))]
    pub current_byte_offset: u64,
}
