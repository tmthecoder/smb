use std::cmp::min;
use std::marker::PhantomData;

use nom::error::ErrorKind;
use nom::IResult;
use serde::{Deserialize, Serialize};

use smb_core::{SMBFromBytes, SMBToBytes};
use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::header::command_code::{LegacySMBCommandCode, SMBCommandCode};
use crate::protocol::header::extra::SMBExtra;
use crate::protocol::header::flags::{LegacySMBFlags, SMBFlags};
use crate::protocol::header::flags2::LegacySMBFlags2;
use crate::protocol::header::status::SMBStatus;

pub mod command_code;
pub mod status;
pub mod flags;
pub mod flags2;
pub mod extra;

pub enum SMBSender {
    Client,
    Server,
}

pub trait Header: SMBFromBytes + SMBToBytes {
    type CommandCode: Into<u64>;

    fn command_code(&self) -> Self::CommandCode;

    fn parse(bytes: &[u8]) -> IResult<&[u8], (Self, Self::CommandCode)> where Self: Sized + SMBFromBytes {
        let (remaining, message) = Self::smb_from_bytes(bytes)
            .map_err(|_e| nom::Err::Error(nom::error::ParseError::from_error_kind(bytes, ErrorKind::MapRes)))?;
        let command = message.command_code();
        // .map_err(|_e| );
        Ok((remaining, (message, command)))
    }

    fn sender(&self) -> SMBSender;
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBFromBytes, SMBToBytes, SMBByteSize)]
#[smb_byte_tag(value = 0xFE, order = 0)]
#[smb_string_tag(value = "SMB", order = 1)]
#[smb_byte_tag(value = 64, order = 2)]
pub struct SMBSyncHeader {
    #[smb_direct(start(fixed = 8))]
    pub channel_sequence: u32,
    #[smb_direct(start(fixed = 12))]
    pub command: SMBCommandCode,
    #[smb_direct(start(fixed = 14))]
    pub credits: u16,
    #[smb_direct(start(fixed = 16))]
    pub flags: SMBFlags,
    #[smb_direct(start(fixed = 20))]
    pub next_command: u32,
    #[smb_direct(start(fixed = 24))]
    pub message_id: u64,
    #[smb_skip(start = 32, length = 4, value = "[0xFF, 0xFE, 0, 0]")]
    pub reserved: PhantomData<[u8; 4]>,
    #[smb_direct(start(fixed = 36))]
    pub tree_id: u32,
    #[smb_direct(start(fixed = 40))]
    pub session_id: u64,
    #[smb_direct(start(fixed = 48))]
    pub signature: [u8; 16],
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBFromBytes, SMBByteSize, SMBToBytes)]
#[smb_byte_tag(0xFE)]
#[smb_string_tag("SMB")]
pub struct LegacySMBHeader {
    #[smb_direct(start(fixed = 4))]
    pub(crate) command: LegacySMBCommandCode,
    #[smb_direct(start(fixed = 5))]
    status: SMBStatus,
    #[smb_direct(start(fixed = 9))]
    flags: LegacySMBFlags,
    #[smb_direct(start(fixed = 10))]
    flags2: LegacySMBFlags2,
    #[smb_direct(start(fixed = 12))]
    extra: SMBExtra,
    #[smb_direct(start(fixed = 22))]
    tid: u16,
    #[smb_direct(start(fixed = 24))]
    pid: u16,
    #[smb_direct(start(fixed = 26))]
    uid: u16,
    #[smb_direct(start(fixed = 28))]
    mid: u16,
}

impl Header for SMBSyncHeader {
    type CommandCode = SMBCommandCode;

    fn command_code(&self) -> Self::CommandCode {
        self.command
    }

    fn sender(&self) -> SMBSender {
        if self.flags.contains(SMBFlags::SERVER_TO_REDIR) {
            SMBSender::Server
        } else {
            SMBSender::Client
        }
    }
}

impl Header for LegacySMBHeader {
    type CommandCode = LegacySMBCommandCode;

    fn command_code(&self) -> Self::CommandCode {
        self.command
    }

    fn sender(&self) -> SMBSender {
        if self.flags.contains(LegacySMBFlags::SERVER_TO_REDIR) {
            SMBSender::Server
        } else {
            SMBSender::Client
        }
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
            credits: 0,
            flags,
            next_command,
            message_id,
            reserved: PhantomData,
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
                credits: 0,
                message_id: legacy_header.mid as u64,
                reserved: PhantomData,
                tree_id: legacy_header.tid as u32,
                session_id: legacy_header.uid as u64,
                signature: [0; 16],
            }),
            _ => None,
        }
    }

    pub fn create_response_header(&self, channel_sequence: u32, session_id: u64, tree_id: u32) -> Self {
        Self {
            command: self.command,
            flags: SMBFlags::SERVER_TO_REDIR,
            channel_sequence,
            next_command: 0,
            credits: self.credits,
            message_id: self.message_id,
            reserved: PhantomData,
            tree_id,
            session_id,
            signature: [0; 16],
        }
    }

    pub fn set_signature(&mut self, signature: &[u8]) {
        self.flags |= SMBFlags::SIGNED;
        self.signature[..min(16, signature.len())]
            .copy_from_slice(&signature[..min(16, signature.len())]);
    }
}
