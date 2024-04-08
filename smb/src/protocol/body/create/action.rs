use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

#[repr(u32)]
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, SMBFromBytes, SMBToBytes, SMBByteSize, TryFromPrimitive)]
pub enum SMBCreateAction {
    FileSuperseded = 0x0,
    FileOpened = 0x1,
    FileCreated = 0x2,
    FileOverwritten = 0x3,
}