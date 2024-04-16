use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TryFromPrimitive, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub enum SMBIoCtlRequestFlags {
    IOCTL = 0x0,
    FSCTL = 0x1,
}