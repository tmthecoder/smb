use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

/// FILE_STANDARD_INFORMATION (MS-FSCC 2.4.41) — 24 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileStandardInformation {
    #[smb_direct(start(fixed = 0))]
    pub allocation_size: u64,
    #[smb_direct(start(fixed = 8))]
    pub end_of_file: u64,
    #[smb_direct(start(fixed = 16))]
    pub number_of_links: u32,
    #[smb_direct(start(fixed = 20))]
    pub delete_pending: u8,
    #[smb_direct(start(fixed = 21))]
    pub directory: u8,
    #[smb_direct(start(fixed = 22))]
    pub reserved: u16,
}
