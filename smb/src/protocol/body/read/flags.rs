use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

bitflags! {
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
    pub struct SMBReadRequestFlags: u8 {
        const UNBUFFERED = 0x01;
        const REQUEST_COMPRESSED = 0x02;
    }
}

#[repr(u32)]
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, SMBToBytes, SMBFromBytes, SMBByteSize, TryFromPrimitive, Copy, Clone)]
pub enum SMBReadResponseFlags {
    None = 0x0,
    RdmaTransform = 0x01,
}

impl_smb_from_bytes_for_bitflag!(SMBReadRequestFlags);
impl_smb_to_bytes_for_bitflag!(SMBReadRequestFlags);
impl_smb_byte_size_for_bitflag!(SMBReadRequestFlags);
