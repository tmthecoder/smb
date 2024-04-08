use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

bitflags! {
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SMBCloseFlags: u16 {
        const POSTQUERY_ATTRIB = 0x01;
    }
}

impl_smb_byte_size_for_bitflag! { SMBCloseFlags }
impl_smb_to_bytes_for_bitflag! { SMBCloseFlags }
impl_smb_from_bytes_for_bitflag! { SMBCloseFlags }