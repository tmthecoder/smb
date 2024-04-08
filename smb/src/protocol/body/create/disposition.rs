use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, SMBFromBytes, SMBToBytes, SMBByteSize, TryFromPrimitive, Serialize, Deserialize)]
pub enum SMBCreateDisposition {
    Supersede = 0x0,
    Open = 0x1,
    Create = 0x2,
    OpenIf = 0x3,
    Overwrite = 0x4,
    OverwriteIf = 0x5,
}