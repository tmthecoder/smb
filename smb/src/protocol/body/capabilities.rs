use bitflags::bitflags;
use serde::{Deserialize, Serialize};

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