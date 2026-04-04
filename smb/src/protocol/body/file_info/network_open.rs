use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::file_attributes::SMBFileAttributes;
use crate::protocol::body::filetime::FileTime;

/// FILE_NETWORK_OPEN_INFORMATION (MS-FSCC 2.4.29) — 56 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileNetworkOpenInformation {
    #[smb_direct(start(fixed = 0))]
    creation_time: FileTime,
    #[smb_direct(start(fixed = 8))]
    last_access_time: FileTime,
    #[smb_direct(start(fixed = 16))]
    last_write_time: FileTime,
    #[smb_direct(start(fixed = 24))]
    change_time: FileTime,
    #[smb_direct(start(fixed = 32))]
    allocation_size: u64,
    #[smb_direct(start(fixed = 40))]
    end_of_file: u64,
    #[smb_direct(start(fixed = 48))]
    file_attributes: SMBFileAttributes,
    #[smb_direct(start(fixed = 52))]
    reserved: u32,
}

impl FileNetworkOpenInformation {
    pub fn new(
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        change_time: FileTime,
        allocation_size: u64,
        end_of_file: u64,
        file_attributes: SMBFileAttributes,
    ) -> Self {
        Self {
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
            allocation_size,
            end_of_file,
            file_attributes,
            reserved: 0,
        }
    }

    pub fn creation_time(&self) -> &FileTime { &self.creation_time }
    pub fn last_access_time(&self) -> &FileTime { &self.last_access_time }
    pub fn last_write_time(&self) -> &FileTime { &self.last_write_time }
    pub fn change_time(&self) -> &FileTime { &self.change_time }
    pub fn allocation_size(&self) -> u64 { self.allocation_size }
    pub fn end_of_file(&self) -> u64 { self.end_of_file }
    pub fn file_attributes(&self) -> SMBFileAttributes { self.file_attributes }
}
