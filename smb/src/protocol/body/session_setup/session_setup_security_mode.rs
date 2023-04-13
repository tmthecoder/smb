use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
    pub struct SessionSetupSecurityMode: u8 {
        const NEGOTIATE_SIGNING_ENABLED = 0x01;
        const NEGOTIATE_SIGNING_REQUIRED = 0x02;
    }
}

impl_smb_byte_size_for_bitflag! {SessionSetupSecurityMode}
impl_smb_from_bytes_for_bitflag! {SessionSetupSecurityMode}