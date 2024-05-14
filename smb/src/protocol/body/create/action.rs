use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

#[repr(u32)]
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, SMBFromBytes, SMBToBytes, SMBByteSize, TryFromPrimitive, Copy, Clone)]
pub enum SMBCreateAction {
    Superseded = 0x0,
    Opened = 0x1,
    Created = 0x2,
    Overwritten = 0x3,
}