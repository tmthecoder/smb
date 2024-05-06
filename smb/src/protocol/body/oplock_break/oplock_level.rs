use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TryFromPrimitive, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub enum SMBOplockLevel {
    None = 0x0,
    II = 0x1,
    Exclusive = 0x8,
}