use bitflags::bitflags;
use nom::bytes::complete::take;
use nom::combinator::map;
use nom::{IResult, Parser};
use nom::number::complete::{le_u16, le_u32, le_u64, le_u8};
use nom::sequence::tuple;
use serde::{Deserialize, Serialize};
use crate::byte_helper::{bytes_to_u16, bytes_to_u32, bytes_to_u64, u16_to_bytes};
use crate::protocol::body::{Capabilities, SecurityMode};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct SMBSessionSetupRequestBody {
    flags: SMBSessionSetupFlags,
    security_mode: SecurityMode,
    capabilities: Capabilities,
    previous_session_id: u64,
    buffer: Vec<u8>
}

impl SMBSessionSetupRequestBody {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (_, (_, flags, security_mode, capabilities, _, security_buffer_offset, security_buffer_len, previous_session_id)) = tuple((
            take(2_usize),
            map(le_u8, SMBSessionSetupFlags::from_bits_truncate),
            map(le_u8, |b: u8| SecurityMode::from_bits_truncate(b.into())),
            map(le_u32, Capabilities::from_bits_truncate),
            take(4_usize),
            map(le_u16, |x| x - 64),
            le_u16,
            le_u64,
        ))(bytes)?;
        let (remaining, buffer) = take(security_buffer_offset)(bytes)
            .and_then(|(remaining, _)| take(security_buffer_len)(remaining))
            .map(|res| (res.0, res.1.to_vec()))?;
        Ok((remaining, Self {
            flags,
            security_mode,
            capabilities,
            previous_session_id,
            buffer
        }))
    }

    pub fn get_buffer_copy(&self) -> Vec<u8> {
        self.buffer.clone()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct SMBSessionSetupResponseBody {
    session_flags: SMBSessionFlags,
    buffer: Vec<u8>
}

impl SMBSessionSetupResponseBody {
    pub fn new(session_flags: SMBSessionFlags, buffer: Vec<u8>) -> Self {
        Self { session_flags, buffer }
    }

    pub fn from_request(request: SMBSessionSetupRequestBody, token: Vec<u8>) -> Option<Self> {
        Some(Self {
            session_flags: SMBSessionFlags::empty(),
            buffer: token
        })
    }
}

impl SMBSessionSetupResponseBody {
    pub fn as_bytes(&self) -> Vec<u8> {
        let security_offset = 72_u16;
        [
            &[9, 0][0..],
            &u16_to_bytes(self.session_flags.bits),
            &u16_to_bytes(security_offset),
            &u16_to_bytes(self.buffer.len() as u16),
            &*self.buffer
        ].concat()
    }
}

bitflags! {
    #[derive(Serialize, Deserialize)]
    pub struct SMBSessionSetupFlags: u8 {
        const SMB2_SESSION_FLAG_BINDING = 0x01;
    }
}

bitflags! {
    #[derive(Serialize, Deserialize)]
    pub struct SMBSessionFlags: u16 {
        const IS_GUEST = 0x01;
        const IS_NULL = 0x02;
        const ENCRYPT_DATA = 0x04;
    }
}