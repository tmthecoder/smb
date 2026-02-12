use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

/// FILE_NAME_INFORMATION (MS-FSCC 2.4.28) — variable length
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileNameInformation {
    #[smb_direct(start(fixed = 0))]
    pub file_name_length: u32,
    #[smb_string(order = 0, start(fixed = 4), length(inner(start = 0, num_type = "u32")), underlying = "u16")]
    pub file_name: String,
}
