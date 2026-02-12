use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

/// FILE_EA_INFORMATION (MS-FSCC 2.4.12) — 4 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileEaInformation {
    #[smb_direct(start(fixed = 0))]
    pub ea_size: u32,
}
