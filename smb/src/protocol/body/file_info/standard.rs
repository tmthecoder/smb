use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

/// FILE_STANDARD_INFORMATION (MS-FSCC 2.4.41) — 24 bytes
///
/// `delete_pending` and `directory` are booleans on the wire (u8: 0 or 1).
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileStandardInformation {
    #[smb_direct(start(fixed = 0))]
    allocation_size: u64,
    #[smb_direct(start(fixed = 8))]
    end_of_file: u64,
    #[smb_direct(start(fixed = 16))]
    number_of_links: u32,
    #[smb_direct(start(fixed = 20))]
    delete_pending: u8,
    #[smb_direct(start(fixed = 21))]
    directory: u8,
    #[smb_direct(start(fixed = 22))]
    reserved: u16,
}

impl FileStandardInformation {
    pub fn new(
        allocation_size: u64,
        end_of_file: u64,
        number_of_links: u32,
        delete_pending: bool,
        directory: bool,
    ) -> Self {
        Self {
            allocation_size,
            end_of_file,
            number_of_links,
            delete_pending: delete_pending as u8,
            directory: directory as u8,
            reserved: 0,
        }
    }

    pub fn allocation_size(&self) -> u64 { self.allocation_size }
    pub fn end_of_file(&self) -> u64 { self.end_of_file }
    pub fn number_of_links(&self) -> u32 { self.number_of_links }
    pub fn delete_pending(&self) -> bool { self.delete_pending != 0 }
    pub fn directory(&self) -> bool { self.directory != 0 }
}
