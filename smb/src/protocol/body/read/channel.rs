use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

#[repr(u32)]
#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize, TryFromPrimitive)]
pub enum SMBRWChannel {
    None = 0x0,
    RdmaV1 = 0x1,
    RdmaV1Invalidate = 0x2,
}