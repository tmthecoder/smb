use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::file_attributes::SMBFileAttributes;
use crate::protocol::body::filetime::FileTime;

/// FILE_NETWORK_OPEN_INFORMATION (MS-FSCC 2.4.29) — 56 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileNetworkOpenInformation {
    #[smb_direct(start(fixed = 0))]
    pub creation_time: FileTime,
    #[smb_direct(start(fixed = 8))]
    pub last_access_time: FileTime,
    #[smb_direct(start(fixed = 16))]
    pub last_write_time: FileTime,
    #[smb_direct(start(fixed = 24))]
    pub change_time: FileTime,
    #[smb_direct(start(fixed = 32))]
    pub allocation_size: u64,
    #[smb_direct(start(fixed = 40))]
    pub end_of_file: u64,
    #[smb_direct(start(fixed = 48))]
    pub file_attributes: SMBFileAttributes,
    #[smb_direct(start(fixed = 52))]
    pub reserved: u32,
}
