use bitflags::bitflags;
use nom::{IResult, Parser};
use nom::bytes::complete::take;
use nom::Err::Error;
use nom::error::ErrorKind;
use nom::number::complete::{le_u16, le_u32};
use serde::{Deserialize, Serialize};

use crate::byte_helper::{bytes_to_u16, bytes_to_u32};
use crate::util::auth::ntlm::{NTLMAuthenticateMessageBody, NTLMChallengeMessageBody, NTLMNegotiateMessageBody};

#[derive(Debug, Deserialize, Serialize)]
pub enum NTLMMessage {
    Negotiate(NTLMNegotiateMessageBody),
    Challenge(NTLMChallengeMessageBody),
    Authenticate(NTLMAuthenticateMessageBody),
    Dummy
}

impl NTLMMessage {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 24 { return None; }
        match bytes_to_u32(&bytes[8..12]) {
            0x01 => Some(NTLMMessage::Negotiate(NTLMNegotiateMessageBody::from_bytes(bytes)?)),
            0x02 => Some(NTLMMessage::Challenge(NTLMChallengeMessageBody::from_bytes(bytes)?)),
            0x03 => Some(NTLMMessage::Authenticate(NTLMAuthenticateMessageBody::from_bytes(bytes)?)),
            _ => None,
        }
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (_, msg_type) = take(8_usize)(bytes)
            .and_then(|(remaining, _)| le_u32(remaining))?;
        match msg_type {
            0x01 => {
                let (remaining, body) = NTLMNegotiateMessageBody::parse(bytes)?;
                Ok((remaining, NTLMMessage::Negotiate(body)))
            },
            0x02 => {
                let (remaining, body) = NTLMChallengeMessageBody::parse(bytes)?;
                Ok((remaining, NTLMMessage::Challenge(body)))
            },
            0x03 => {
                let (remaining, body) = NTLMAuthenticateMessageBody::parse(bytes)?;
                Ok((remaining, NTLMMessage::Authenticate(body)))
            },
            _ => Err(Error(nom::error::Error::new(bytes, ErrorKind::Fail)))
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            NTLMMessage::Negotiate(msg) => msg.as_bytes(),
            NTLMMessage::Challenge(msg) => msg.as_bytes(),
            NTLMMessage::Authenticate(msg) => msg.as_bytes(),
            NTLMMessage::Dummy => Vec::new(),
        }
    }
}

bitflags! {
    #[derive(Deserialize, Serialize)]
    pub struct NTLMNegotiateFlags: u32 {
        const UNICODE_ENCODING = 0x01;
        const OEM_ENCODING = 0x02;
        const TARGET_NAME_SUPPLOED = 0x04;
        const SIGN = 0x10;
        const SEAL = 0x20;
        const DATAGRAM = 0x40;
        const LAN_MANAGER_SESSION_KEY = 0x80;
        const NTLM_SESSION_SECURITY = 0x200;
        const ANONYMOUS = 0x800;
        const DOMAIN_NAME_SUPPLIED = 0x1000;
        const WORKSTATION_NAME_SUPPLIED = 0x2000;
        const ALWAYS_SIGN = 0x8000;
        const TARGET_TYPE_DOMAIN = 0x10000;
        const TARGET_TYPE_SERVER = 0x20000;
        const EXTENDED_SESSION_SECURITY = 0x80000;
        const IDENIFY = 0x100000;
        const REQUEST_LM_SESSION_KEY = 0x400000;
        const TARGET_INFO = 0x800000;
        const VERSION = 0x2000000;
        const USE_128_BIT_ENCRYPTION = 0x20000000;
        const KEY_EXCHANGE = 0x40000000;
        const USE_56_BIT_ENCRYPTION = 0x80000000;
    }
}

pub(crate) fn read_ntlm_buffer_ptr(buffer: &[u8], offset: usize) -> Option<Vec<u8>> {
    let length = bytes_to_u16(&buffer[offset..(offset + 2)]) as usize;
    let offset = offset + 4;
    let buffer_offset = bytes_to_u32(&buffer[offset..(offset + 4)]) as usize;
    if buffer.len() < buffer_offset + length {
        return None;
    }
    Some(buffer[buffer_offset..(buffer_offset + length)].to_vec())
}

pub(crate) fn parse_ntlm_buffer_ptr(bytes: &[u8]) -> IResult<&[u8], &[u8]> {
    let (remaining, length) = le_u16(bytes)?;
    let (_, buffer_offset) = take(2_usize)(remaining).and_then(|(remaining, _)| le_u32(remaining))?;
    take(buffer_offset as usize)(bytes).and_then(|(remaining, _)| take(length as usize)(remaining))
}