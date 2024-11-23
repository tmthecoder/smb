use bitflags::bitflags;
use serde::{Deserialize, Serialize};

bitflags! {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
    pub struct SMBTreeConnectCapabilities: u32 {
        const DFS                     = 0x008;
        const CONTINUOUS_AVAILABILITY = 0x010;
        const SCALEOUT                = 0x020;
        const CLUSTER                 = 0x040;
        const ASYMMETRIC              = 0x080;
        const REDIRECT_TO_OWNER       = 0x100;
    }
}