use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SMBQueryInfoFlags: u32 {
        const RESTART_SCANS = 0x1;
        const RETURN_SINGLE_ENTRY = 0x2;
        const INDEX_SPECIFIED = 0x4;
    }
}

impl_smb_byte_size_for_bitflag!(SMBQueryInfoFlags);
impl_smb_to_bytes_for_bitflag!(SMBQueryInfoFlags);
impl_smb_from_bytes_for_bitflag!(SMBQueryInfoFlags);
