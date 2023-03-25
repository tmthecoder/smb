use bitflags::bitflags;
use serde::{Deserialize, Serialize};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
    pub struct SecurityMode: u16 {
        const NEGOTIATE_SIGNING_ENABLED = 0x01;
        const NEGOTIATE_SIGNING_REQUIRED = 0x02;
    }
}