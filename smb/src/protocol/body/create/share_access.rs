use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

bitflags! {
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SMBShareAccess: u32 {
        const READ = 0x1;
        const WRITE = 0x2;
        const DELETE = 0x4;
    }
}

impl_smb_byte_size_for_bitflag! { SMBShareAccess }
impl_smb_to_bytes_for_bitflag! { SMBShareAccess }
impl_smb_from_bytes_for_bitflag! { SMBShareAccess }