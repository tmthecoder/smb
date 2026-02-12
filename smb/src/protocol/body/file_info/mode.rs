use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

/// FILE_MODE_INFORMATION (MS-FSCC 2.4.26) — 4 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileModeInformation {
    #[smb_direct(start(fixed = 0))]
    pub mode: u32,
}
