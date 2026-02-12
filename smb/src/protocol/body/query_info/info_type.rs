use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, TryFromPrimitive, SMBToBytes, SMBFromBytes, SMBByteSize, Serialize, Deserialize)]
pub enum SMBInfoType {
    File = 1,
    Filesystem = 2,
    Security = 3,
    Quota = 4,
}