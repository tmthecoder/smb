use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use smb_core::{SMBFromBytes, SMBResult};
use smb_core::error::SMBError;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
    pub struct LegacySMBFlags2: u16 {
        const UNICODE_STRINGS    = 0b1000000000000000;
        const ERROR_CODE_STATUS  = 0b100000000000000; // 32_BIT_STATUS
        const READ_IF_EXECUTE    = 0b10000000000000;
        const DFS_PATHNAME       = 0b1000000000000;
        const EXTENDED_SECURITY  = 0b100000000000;
        const RESERVED_01        = 0b10000000000;
        const RESERVED_02        = 0b1000000000;
        const RESERVED_03        = 0b100000000;
        const RESERVED_04        = 0b10000000;
        const IS_LONG_NAME       = 0b1000000;
        const RESERVED_05        = 0b100000;
        const RESERVED_06        = 0b1000;
        const SECURITY_SIGNATURE = 0b100;
        const EAS                = 0b10;
        const KNOWS_LONG_NAMES   = 0b1;
    }
}

impl SMBFromBytes for LegacySMBFlags2 {
    fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> where Self: Sized {
        let flags = Self::from_bits_truncate(u16::from_le_bytes(<[u8; 2]>::try_from(&input[0..2])
            .map_err(|_e| SMBError::ParseError("Invalid byte slice".into()))?));
        Ok((&input[2..], flags))
    }
}