use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

bitflags! {
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
    pub struct SMBLockFlags: u32 {
        const SHARED = 0x1;
        const EXCLUSIVE = 0x2;
        const UNLOCK = 0x3;
        const FAIL_IMMEDIATELY = 0x4;
    }
}

impl_smb_from_bytes_for_bitflag!(SMBLockFlags);
impl_smb_to_bytes_for_bitflag!(SMBLockFlags);
impl_smb_byte_size_for_bitflag!(SMBLockFlags);