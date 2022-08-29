use bitflags::bitflags;
use serde::{Serialize, Deserialize};

bitflags! {
    #[derive(Default, Serialize, Deserialize)]
    pub struct SMBFlags2: u16 {
        const UNICODE_STRINGS    = 0b1000000000000000;
        const ERROR_CODE_STATUS  = 0b100000000000000; // 32_BIT_STATUS
        const READ_IF_EXECUTE    = 0b10000000000000;
        const DFS_PATHNAME       = 0b1000000000000;
        const EXTENDED_SECURITY  = 0b100000000000;
        const IS_LONG_NAME       = 0b1000000;
        const SECURITY_SIGNATURE = 0b100;
        const EAS                = 0b10;
        const KNOWS_LONG_NAMES   = 0b1;
    }
}

impl SMBFlags2 {
    pub fn clear(&mut self) {
        self.bits = 0;
    }
}