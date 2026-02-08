use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
   pub struct Capabilities: u32 {
      const DFS                = 0x01;
      const LEASING            = 0x02;
      const LARGE_MTU          = 0x04;
      const MULTI_CHANNEL      = 0x08;
      const PERSISTENT_HANDLES = 0x10;
      const DIRECTORY_LISTING  = 0x20;
      const ENCRYPTION         = 0x40;
   }
}

impl_smb_byte_size_for_bitflag! { Capabilities }
impl_smb_from_bytes_for_bitflag! { Capabilities }
impl_smb_to_bytes_for_bitflag! { Capabilities }

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBFromBytes, SMBToBytes};

    /// MS-SMB2 2.2.3: Capabilities flags
    #[test]
    fn capabilities_values_match_spec() {
        assert_eq!(Capabilities::DFS.bits(), 0x00000001);
        assert_eq!(Capabilities::LEASING.bits(), 0x00000002);
        assert_eq!(Capabilities::LARGE_MTU.bits(), 0x00000004);
        assert_eq!(Capabilities::MULTI_CHANNEL.bits(), 0x00000008);
        assert_eq!(Capabilities::PERSISTENT_HANDLES.bits(), 0x00000010);
        assert_eq!(Capabilities::DIRECTORY_LISTING.bits(), 0x00000020);
        assert_eq!(Capabilities::ENCRYPTION.bits(), 0x00000040);
    }

    #[test]
    fn capabilities_round_trip() {
        let caps = Capabilities::DFS | Capabilities::ENCRYPTION | Capabilities::LARGE_MTU;
        let bytes = caps.smb_to_bytes();
        assert_eq!(bytes.len(), 4);
        let (_, parsed) = Capabilities::smb_from_bytes(&bytes).unwrap();
        assert_eq!(parsed, caps);
    }
}