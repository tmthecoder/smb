use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

bitflags! {
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SMBWriteFlags: u8 {
        const WRITE_THROUGH = 0x01;
        const WRITE_UNBUFFERED = 0x02;
    }
}

impl_smb_from_bytes_for_bitflag!(SMBWriteFlags);
impl_smb_to_bytes_for_bitflag!(SMBWriteFlags);
impl_smb_byte_size_for_bitflag!(SMBWriteFlags);
