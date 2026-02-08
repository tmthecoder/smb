use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
    pub struct NegotiateSecurityMode: u16 {
        const NEGOTIATE_SIGNING_ENABLED = 0x01;
        const NEGOTIATE_SIGNING_REQUIRED = 0x02;
    }
}

impl_smb_byte_size_for_bitflag! {NegotiateSecurityMode}
impl_smb_from_bytes_for_bitflag! {NegotiateSecurityMode}
impl_smb_to_bytes_for_bitflag! {NegotiateSecurityMode}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBFromBytes, SMBToBytes};

    #[test]
    fn security_mode_values() {
        assert_eq!(NegotiateSecurityMode::NEGOTIATE_SIGNING_ENABLED.bits(), 0x0001);
        assert_eq!(NegotiateSecurityMode::NEGOTIATE_SIGNING_REQUIRED.bits(), 0x0002);
    }

    #[test]
    fn security_mode_round_trip() {
        let mode = NegotiateSecurityMode::NEGOTIATE_SIGNING_ENABLED
            | NegotiateSecurityMode::NEGOTIATE_SIGNING_REQUIRED;
        let bytes = mode.smb_to_bytes();
        assert_eq!(bytes, [0x03, 0x00]);
        let (_, parsed) = NegotiateSecurityMode::smb_from_bytes(&bytes).unwrap();
        assert_eq!(parsed, mode);
    }
}