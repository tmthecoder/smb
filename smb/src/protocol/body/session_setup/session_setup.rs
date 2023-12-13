use bitflags::bitflags;
use nom::bytes::complete::take;
use nom::combinator::map;
use nom::IResult;
use nom::number::complete::{le_u16, le_u32, le_u64, le_u8};
use nom::sequence::tuple;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::byte_helper::u16_to_bytes;
use crate::protocol::body::Capabilities;
use crate::protocol::body::session_setup::SessionSetupSecurityMode;
use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBFromBytes, SMBByteSize, SMBToBytes)]
#[smb_byte_tag(value = 25)]
pub struct SMBSessionSetupRequest {
    #[smb_direct(start(fixed = 2))]
    flags: SMBSessionSetupFlags,
    #[smb_direct(start(fixed = 3))]
    security_mode: SessionSetupSecurityMode,
    #[smb_direct(start(fixed = 4))]
    capabilities: Capabilities,
    #[smb_direct(start(fixed = 16))]
    previous_session_id: u64,
    #[smb_buffer(offset(inner(start = 12, num_type = "u16", subtract = 64)), length(inner(start = 14, num_type = "u16")))]
    buffer: Vec<u8>,
}

impl SMBSessionSetupRequest {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (
            _,
            (
                _,
                flags,
                security_mode,
                capabilities,
                _,
                security_buffer_offset,
                security_buffer_len,
                previous_session_id,
            ),
        ) = tuple((
            take(2_usize),
            map(le_u8, SMBSessionSetupFlags::from_bits_truncate),
            map(le_u8, SessionSetupSecurityMode::from_bits_truncate),
            map(le_u32, Capabilities::from_bits_truncate),
            take(4_usize),
            map(le_u16, |x| x - 64),
            le_u16,
            le_u64,
        ))(bytes)?;
        let (remaining, buffer) = take(security_buffer_offset)(bytes)
            .and_then(|(remaining, _)| take(security_buffer_len)(remaining))
            .map(|res| (res.0, res.1.to_vec()))?;
        Ok((
            remaining,
            Self {
                flags,
                security_mode,
                capabilities,
                previous_session_id,
                buffer,
            },
        ))
    }

    pub fn get_buffer_copy(&self) -> Vec<u8> {
        self.buffer.clone()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBToBytes, SMBFromBytes, SMBByteSize)]
#[smb_byte_tag(value = 9)]
pub struct SMBSessionSetupResponse {
    #[smb_direct(start(fixed = 2))]
    session_flags: SMBSessionFlags,
    #[smb_buffer(offset(inner(start = 4, num_type = "u16", subtract = 64, min_val = 72)), length(inner(start = 6, num_type = "u16")))]
    buffer: Vec<u8>,
}

impl SMBSessionSetupResponse {
    pub fn new(session_flags: SMBSessionFlags, buffer: Vec<u8>) -> Self {
        Self {
            session_flags,
            buffer,
        }
    }

    pub fn from_request(request: SMBSessionSetupRequest, token: Vec<u8>) -> Option<Self> {
        Some(Self {
            session_flags: SMBSessionFlags::empty(),
            buffer: token,
        })
    }
}

impl SMBSessionSetupResponse {
    pub fn as_bytes(&self) -> Vec<u8> {
        let security_offset = 72_u16;
        [
            &[9, 0][0..],
            &u16_to_bytes(self.session_flags.bits()),
            &u16_to_bytes(security_offset),
            &u16_to_bytes(self.buffer.len() as u16),
            &*self.buffer,
        ]
            .concat()
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
    pub struct SMBSessionSetupFlags: u8 {
        const SMB2_SESSION_FLAG_BINDING = 0x01;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
    pub struct SMBSessionFlags: u16 {
        const IS_GUEST = 0x01;
        const IS_NULL = 0x02;
        const ENCRYPT_DATA = 0x04;
    }
}

impl_smb_byte_size_for_bitflag! {SMBSessionSetupFlags SMBSessionFlags}
impl_smb_from_bytes_for_bitflag! {SMBSessionSetupFlags SMBSessionFlags}
impl_smb_to_bytes_for_bitflag! {SMBSessionSetupFlags SMBSessionFlags}
