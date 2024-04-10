use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

bitflags! {
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SMBChangeNotifyFlags: u16 {
        const WATCH_TREE = 0x01;
    }
}

impl_smb_byte_size_for_bitflag!(SMBChangeNotifyFlags);
impl_smb_to_bytes_for_bitflag!(SMBChangeNotifyFlags);
impl_smb_from_bytes_for_bitflag!(SMBChangeNotifyFlags);
