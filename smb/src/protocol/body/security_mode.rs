use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use smb_core::{SMBFromBytes, SMBResult};
use smb_core::error::SMBError;

use crate::util::flags_helper::impl_smb_from_bytes;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
    pub struct SecurityMode: u16 {
        const NEGOTIATE_SIGNING_ENABLED = 0x01;
        const NEGOTIATE_SIGNING_REQUIRED = 0x02;
    }
}

impl SMBFromBytes for SecurityMode {
    fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> where Self: Sized {
        impl_smb_from_bytes!(u16, input, 2)
    }
}