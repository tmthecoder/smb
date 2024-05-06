use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TryFromPrimitive, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub enum SMBInfoType {
    File = 0x1,
    FileSystem = 0x2,
    Security = 0x3,
    Quota = 0x4,
}