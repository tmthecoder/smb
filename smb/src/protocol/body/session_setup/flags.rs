use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
    pub struct SMBSessionSetupFlags: u8 {
        const BINDING = 0x01;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
    pub struct SMBSessionFlags: u16 {
        const IS_GUEST = 0x01;
        const IS_NULL = 0x02;
        const ENCRYPT_DATA = 0x04;
    }
}

impl_smb_byte_size_for_bitflag! {SMBSessionSetupFlags SMBSessionFlags}
impl_smb_from_bytes_for_bitflag! {SMBSessionSetupFlags SMBSessionFlags}
impl_smb_to_bytes_for_bitflag! {SMBSessionSetupFlags SMBSessionFlags}