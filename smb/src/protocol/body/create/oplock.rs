use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, SMBFromBytes, SMBToBytes, SMBByteSize, TryFromPrimitive, Serialize, Deserialize)]
pub enum SMBOplockLevel {
    None = 0x0,
    II = 0x1,
    Exclusive = 0x8,
    Batch = 0x9,
    Lease = 0xFF,
}