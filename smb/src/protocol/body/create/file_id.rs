use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct SMBFileId {
    #[smb_direct(start(fixed = 0))]
    pub persistent: u64,
    #[smb_direct(start(fixed = 8))]
    pub volatile: u64,
}