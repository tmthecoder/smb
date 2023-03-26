use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use smb_core::{SMBFromBytes, SMBResult};
use smb_core::error::SMBError;

use crate::util::flags_helper::impl_smb_for_bytes_for_bitflag;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
    pub struct LegacySMBFlags: u8 {
        const SERVER_TO_REDIR      = 0b10000000;
        const REQUEST_BATCH_OPLOCK = 0b1000000;
        const REQUEST_OPLOCK       = 0b100000;
        const CANONICAL_PATHNAMES  = 0b10000;
        const CASELESS_PATHNAMES   = 0b1000;
        const RESERVED             = 0b100;
        const CLIENT_BUF_AVAIL     = 0b10;
        const SUPPORT_LOCKREAD     = 0b1;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
    pub struct SMBFlags: u32 {
        const SERVER_TO_REDIR = 0x00000001;
        const ASYNC_COMMAND = 0x00000002;
        const RELATED_OPERATIONS = 0x00000004;
        const SIGNED = 0x00000008;
        const PRIORITY_MASK = 0x00000070;
        const DFS_OPERATIONS = 0x10000000;
        const REPLAY_OPERATION = 0x20000000;
    }
}

impl Default for LegacySMBFlags {
    fn default() -> Self {
        LegacySMBFlags::CANONICAL_PATHNAMES | LegacySMBFlags::CASELESS_PATHNAMES
    }
}

impl_smb_for_bytes_for_bitflag! { SMBFlags LegacySMBFlags }