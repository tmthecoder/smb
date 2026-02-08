use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

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

impl_smb_byte_size_for_bitflag! { SMBFlags LegacySMBFlags }
impl_smb_from_bytes_for_bitflag! { SMBFlags LegacySMBFlags }
impl_smb_to_bytes_for_bitflag! { SMBFlags LegacySMBFlags }

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBFromBytes, SMBToBytes};

    /// MS-SMB2 2.2.1: SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001
    #[test]
    fn server_to_redir_value() {
        assert_eq!(SMBFlags::SERVER_TO_REDIR.bits(), 0x00000001);
    }

    /// MS-SMB2 2.2.1: SMB2_FLAGS_ASYNC_COMMAND = 0x00000002
    #[test]
    fn async_command_value() {
        assert_eq!(SMBFlags::ASYNC_COMMAND.bits(), 0x00000002);
    }

    /// MS-SMB2 2.2.1: SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004
    #[test]
    fn related_operations_value() {
        assert_eq!(SMBFlags::RELATED_OPERATIONS.bits(), 0x00000004);
    }

    /// MS-SMB2 2.2.1: SMB2_FLAGS_SIGNED = 0x00000008
    #[test]
    fn signed_value() {
        assert_eq!(SMBFlags::SIGNED.bits(), 0x00000008);
    }

    /// MS-SMB2 2.2.1: SMB2_FLAGS_DFS_OPERATIONS = 0x10000000
    #[test]
    fn dfs_operations_value() {
        assert_eq!(SMBFlags::DFS_OPERATIONS.bits(), 0x10000000);
    }

    /// MS-SMB2 2.2.1: SMB2_FLAGS_REPLAY_OPERATION = 0x20000000
    #[test]
    fn replay_operation_value() {
        assert_eq!(SMBFlags::REPLAY_OPERATION.bits(), 0x20000000);
    }

    #[test]
    fn flags_serialization_is_4_bytes_le() {
        let flags = SMBFlags::SERVER_TO_REDIR | SMBFlags::SIGNED;
        let bytes = flags.smb_to_bytes();
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes, [0x09, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn flags_round_trip() {
        let flags = SMBFlags::SERVER_TO_REDIR | SMBFlags::ASYNC_COMMAND | SMBFlags::DFS_OPERATIONS;
        let bytes = flags.smb_to_bytes();
        let (_, parsed) = SMBFlags::smb_from_bytes(&bytes).unwrap();
        assert_eq!(parsed, flags);
    }
}