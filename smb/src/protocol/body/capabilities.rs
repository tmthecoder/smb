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