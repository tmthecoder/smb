use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

/// FILE_ACCESS_INFORMATION (MS-FSCC 2.4.1) — 4 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileAccessInformation {
    #[smb_direct(start(fixed = 0))]
    pub access_flags: u32,
}
