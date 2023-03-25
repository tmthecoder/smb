use bitflags::bitflags;
use nom::bytes::complete::take;
use nom::Err::Error;
use nom::error::ErrorKind;
use nom::IResult;
use nom::number::complete::{le_u16, le_u32};
use serde::{Deserialize, Serialize};

use crate::util::as_bytes::AsByteVec;
use crate::util::auth::ntlm::{NTLMAuthenticateMessageBody, NTLMChallengeMessageBody, NTLMNegotiateMessageBody};

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Clone)]
pub enum NTLMMessage {
    Negotiate(NTLMNegotiateMessageBody),
    Challenge(NTLMChallengeMessageBody),
    Authenticate(NTLMAuthenticateMessageBody),
    Dummy
}

impl NTLMMessage {
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
        self.as_byte_vec()
    }
}

impl AsByteVec for NTLMMessage {
    fn as_byte_vec(&self) -> Vec<u8> {
        match self {
            NTLMMessage::Negotiate(msg) => msg.as_bytes(),
            NTLMMessage::Challenge(msg) => msg.as_bytes(),
            NTLMMessage::Authenticate(msg) => msg.as_bytes(),
            NTLMMessage::Dummy => Vec::new(),
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
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

pub(crate) fn parse_ntlm_buffer_fields(bytes: &[u8]) -> IResult<&[u8], (u16, u32)> {
    let (remaining, length) = le_u16(bytes)?;
    let (remaining, buffer_offset) = take(2_usize)(remaining).and_then(|(remaining, _)| le_u32(remaining))?;
    Ok((remaining, (length, buffer_offset)))
}
