use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, SMBFromBytes, SMBToBytes, SMBByteSize, TryFromPrimitive, Serialize, Deserialize)]
pub enum SMBImpersonationLevel {
    Anonymous = 0x0,
    Identification = 0x1,
    Impersonation = 0x2,
    Delegate = 0x3,
} 