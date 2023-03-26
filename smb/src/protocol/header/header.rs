use serde::{Deserialize, Serialize};

use smb_derive::SMBFromBytes;

use crate::byte_helper::{u16_to_bytes, u32_to_bytes, u64_to_bytes};
use crate::protocol::header::{
    Header, LegacySMBCommandCode, LegacySMBFlags, LegacySMBFlags2, SMBCommandCode, SMBExtra,
    SMBFlags, SMBStatus,
};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBFromBytes)]
#[byte_tag(0xFE)]
#[string_tag("SMB")]
pub struct SMBSyncHeader {
    #[direct(start = 12)]
    pub command: SMBCommandCode,
    #[direct(start = 8)]
    channel_sequence: u32,
    // status in smb2
    #[direct(start = 16)]
    flags: SMBFlags,
    #[direct(start = 20)]
    next_command: u32,
    #[direct(start = 24)]
    message_id: u64,
    #[direct(start = 36)]
    tree_id: u32,
    #[direct(start = 40)]
    session_id: u64,
    #[direct(start = 48)]
    signature: [u8; 16],
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBFromBytes)]
#[byte_tag(0xFE)]
#[string_tag("SMB")]
pub struct LegacySMBHeader {
    #[direct(start = 4)]
    pub(crate) command: LegacySMBCommandCode,
    #[direct(start = 5)]
    status: SMBStatus,
    #[direct(start = 9)]
    flags: LegacySMBFlags,
    #[direct(start = 10)]
    flags2: LegacySMBFlags2,
    #[direct(start = 12)]
    extra: SMBExtra,
    #[direct(start = 22)]
    tid: u16,
    #[direct(start = 24)]
    pid: u16,
    #[direct(start = 26)]
    uid: u16,
    #[direct(start = 28)]
    mid: u16,
}

impl Header for SMBSyncHeader {
    type CommandCode = SMBCommandCode;

    fn command_code(&self) -> Self::CommandCode {
        self.command
    }

    fn as_bytes(&self) -> Vec<u8> {
        [
            &[0xFE_u8],
            &b"SMB"[0..],
            &[64, 0],                             // Structure size,
            &[1, 0],                              // Credit
            &u32_to_bytes(self.channel_sequence), // Reserved/Status/TODO
            &u16_to_bytes(self.command as u16),
            &[1, 0], // CreditResponse,
            &u32_to_bytes(self.flags.bits()),
            &[0; 4], // Next Command,
            &u64_to_bytes(self.message_id),
            &[0, 0, 0xFE, 0xFF], // Reserved
            &u32_to_bytes(self.tree_id),
            &u64_to_bytes(self.session_id),
            &self.signature,
        ]
        .concat()
    }
}

impl Header for LegacySMBHeader {
    type CommandCode = LegacySMBCommandCode;

    fn command_code(&self) -> Self::CommandCode {
        self.command
    }

    fn as_bytes(&self) -> Vec<u8> {
        [
            &[0xFF_u8],
            &b"SMB"[0..],
            &[self.command as u8],
            &*self.status.as_bytes(),
            &[self.flags.bits()],
            &u16_to_bytes(self.flags2.bits()),
            &*self.extra.as_bytes(),
            &u16_to_bytes(self.tid),
            &u16_to_bytes(self.pid),
            &u16_to_bytes(self.uid),
            &u16_to_bytes(self.mid),
        ]
        .concat()
    }
}

impl SMBSyncHeader {
    pub fn new(
        command: SMBCommandCode,
        flags: SMBFlags,
        next_command: u32,
        message_id: u64,
        tree_id: u32,
        session_id: u64,
        signature: [u8; 16],
    ) -> Self {
        SMBSyncHeader {
            command,
            channel_sequence: 0,
            flags,
            next_command,
            message_id,
            tree_id,
            session_id,
            signature,
        }
    }

    pub fn from_legacy_header(legacy_header: LegacySMBHeader) -> Option<Self> {
        match legacy_header.command {
            LegacySMBCommandCode::Negotiate => Some(Self {
                command: SMBCommandCode::LegacyNegotiate,
                flags: SMBFlags::empty(),
                channel_sequence: 0,
                next_command: 0,
                message_id: legacy_header.mid as u64,
                tree_id: legacy_header.tid as u32,
                session_id: legacy_header.uid as u64,
                signature: [0; 16],
            }),
            _ => None,
        }
    }

    pub fn create_response_header(&self, channel_sequence: u32, session_id: u64) -> Self {
        Self {
            command: self.command,
            flags: SMBFlags::SERVER_TO_REDIR,
            channel_sequence,
            next_command: 0,
            message_id: self.message_id,
            tree_id: self.tree_id,
            session_id,
            signature: [0; 16],
        }
    }
}
