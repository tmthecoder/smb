use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

bitflags! {
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
    pub struct SMBQueryDirectoryFlags: u8 {
        const RESTART_SCANS = 0x1;
        const RETURN_SINGLE_ENTRY = 0x2;
        const INDEX_SPECIFIED = 0x4;
        const REOPEN = 0x10;
    }
}

impl_smb_from_bytes_for_bitflag!(SMBQueryDirectoryFlags);
impl_smb_to_bytes_for_bitflag!(SMBQueryDirectoryFlags);
impl_smb_byte_size_for_bitflag!(SMBQueryDirectoryFlags);