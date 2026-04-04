use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

/// FILE_NAME_INFORMATION (MS-FSCC 2.4.28) — variable length
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileNameInformation {
    #[smb_direct(start(fixed = 0))]
    file_name_length: u32,
    #[smb_string(order = 0, start(fixed = 4), length(inner(start = 0, num_type = "u32")), underlying = "u16")]
    file_name: String,
}

impl FileNameInformation {
    pub fn new(file_name_length: u32, file_name: String) -> Self {
        Self { file_name_length, file_name }
    }

    pub fn file_name_length(&self) -> u32 { self.file_name_length }
    pub fn file_name(&self) -> &str { &self.file_name }
}
