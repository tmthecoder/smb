use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::file_attributes::SMBFileAttributes;
use crate::protocol::body::filetime::FileTime;

/// FILE_BASIC_INFORMATION (MS-FSCC 2.4.7) — 40 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileBasicInformation {
    #[smb_direct(start(fixed = 0))]
    pub creation_time: FileTime,
    #[smb_direct(start(fixed = 8))]
    pub last_access_time: FileTime,
    #[smb_direct(start(fixed = 16))]
    pub last_write_time: FileTime,
    #[smb_direct(start(fixed = 24))]
    pub change_time: FileTime,
    #[smb_direct(start(fixed = 32))]
    pub file_attributes: SMBFileAttributes,
    #[smb_direct(start(fixed = 36))]
    pub reserved: u32,
}
