use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

/// FILE_ALIGNMENT_INFORMATION (MS-FSCC 2.4.3) — 4 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileAlignmentInformation {
    #[smb_direct(start(fixed = 0))]
    pub alignment_requirement: u32,
}
