use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use smb_core::{SMBFromBytes, SMBResult};
use smb_core::error::SMBError;

use crate::util::flags_helper::impl_smb_from_bytes;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
   pub struct Capabilities: u32 {
      const GLOBAL_CAP_DFS                = 0x01;
      const GLOBAL_CAP_LEASING            = 0x02;
      const GLOBAL_CAP_LARGE_MTU          = 0x04;
      const GLOBAL_CAP_MULTI_CHANNEL      = 0x08;
      const GLOBAL_CAP_PERSISTENT_HANDLES = 0x10;
      const GLOBAL_CAP_DIRECTORY_LISTING  = 0x20;
      const GLOBAL_CAP_ENCRYPTION         = 0x40;
   }
}

impl SMBFromBytes for Capabilities {
    fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> where Self: Sized {
        impl_smb_from_bytes!(u32, input, 4)
    }
}