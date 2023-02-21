use nom::bytes::complete::{tag, take};
use nom::combinator::{map, map_opt, map_res};
use nom::number::complete::le_u8;
use nom::number::streaming::{le_u16, le_u32, le_u64};
use nom::sequence::tuple;
use nom::IResult;
use serde::{Deserialize, Serialize};

use crate::byte_helper::{
    bytes_to_u16, bytes_to_u32, bytes_to_u64, u16_to_bytes, u32_to_bytes, u64_to_bytes,
};
use crate::protocol::header::{
    Header, LegacySMBCommandCode, LegacySMBFlags, LegacySMBFlags2, SMBCommandCode, SMBExtra,
    SMBFlags, SMBStatus,
};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct SMBSyncHeader {
    pub command: SMBCommandCode,
    channel_sequence: u32, // status in smb2
    flags: SMBFlags,
    next_command: u32,
    message_id: u64,
    tree_id: u32,
    session_id: u64,
    signature: [u8; 16],
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct LegacySMBHeader {
    pub(crate) command: LegacySMBCommandCode,
    status: SMBStatus,
    flags: LegacySMBFlags,
    flags2: LegacySMBFlags2,
    extra: SMBExtra,
    tid: u16,
    pid: u16,
    uid: u16,
    mid: u16,
}

impl Header for SMBSyncHeader {
    type CommandCode = SMBCommandCode;

    fn parse(bytes: &[u8]) -> IResult<&[u8], (Self, Self::CommandCode)> {
        map(
            tuple((
                tag([0xFE]),
                tag(b"SMB"),
                map(le_u16, |x| x == 64),
                take(2_usize),
                le_u32,
                map_res(le_u16, SMBCommandCode::try_from),
                take(2_usize),
                map(le_u32, SMBFlags::from_bits_truncate),
                le_u32,
                le_u64,
                take(4_usize),
                le_u32,
                le_u64,
                map_res(take(16_usize), <([u8; 16])>::try_from),
            )),
            |(
                _,
                _,
                _,
                _,
                channel_sequence,
                command,
                _,
                flags,
                next_command,
                message_id,
                _,
                tree_id,
                session_id,
                signature,
            )| {
                (
                    Self {
                        command,
                        channel_sequence,
                        flags,
                        next_command,
                        message_id,
                        tree_id,
                        session_id,
                        signature,
                    },
                    command,
                )
            },
        )(bytes)
    }

    fn as_bytes(&self) -> Vec<u8> {
        [
            &[0xFE_u8],
            &b"SMB"[0..],
            &[64, 0],                             // Structure size,
            &[0; 2],                              // Credit
            &u32_to_bytes(self.channel_sequence), // Reserved/Status/TODO
            &u16_to_bytes(self.command as u16),
            &[0; 2], // CreditResponse,
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

    fn parse(bytes: &[u8]) -> IResult<&[u8], (Self, Self::CommandCode)> {
        map(
            tuple((
                tag([0xFE]),
                tag(b"SMB"),
                map_res(le_u8, LegacySMBCommandCode::try_from),
                SMBStatus::parse,
                map(le_u8, LegacySMBFlags::from_bits_truncate),
                map(le_u16, LegacySMBFlags2::from_bits_truncate),
                SMBExtra::parse,
                le_u16,
                le_u16,
                le_u16,
                le_u16,
            )),
            |(_, _, command, status, flags, flags2, extra, tid, pid, uid, mid)| {
                (
                    Self {
                        command,
                        status,
                        flags,
                        flags2,
                        extra,
                        tid,
                        pid,
                        uid,
                        mid,
                    },
                    command,
                )
            },
        )(bytes)
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

    pub fn create_response_header(&self, channel_sequence: u32) -> Self {
        Self {
            command: self.command,
            flags: SMBFlags::SERVER_TO_REDIR,
            channel_sequence,
            next_command: 0,
            message_id: self.message_id,
            tree_id: self.tree_id,
            session_id: self.session_id,
            signature: [1; 16],
        }
    }
}
