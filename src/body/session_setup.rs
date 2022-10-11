use crate::body::{Capabilities, SecurityMode};
use bitflags::bitflags;
use libgssapi::context::ServerCtx;
use serde::{Deserialize, Serialize};
use crate::byte_helper::{bytes_to_u16, bytes_to_u32, bytes_to_u64, u16_to_bytes};
use crate::gss_helper::get_resp_buffer;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBSessionSetupRequestBody {
    flags: SMBSessionSetupFlags,
    security_mode: SecurityMode,
    capabilities: Capabilities,
    previous_session_id: u64,
    buffer: Vec<u8>
}

impl SMBSessionSetupRequestBody {
    pub fn from_bytes(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < 25 { return None; }
        let security_buffer_offset = (bytes_to_u16(&bytes[12..14]) - 64) as usize;
        let security_buffer_len = bytes_to_u16(&bytes[14..16]) as usize;
        if bytes.len() < 24 + (security_buffer_len as usize) { return None }
        let flags = SMBSessionSetupFlags::from_bits_truncate(bytes[2]);
        let security_mode = SecurityMode::from_bits_truncate(bytes[3]);
        let capabilities = Capabilities::from_bits_truncate(bytes_to_u32(&bytes[4..8]) as u8);
        let previous_session_id = bytes_to_u64(&bytes[16..24]);
        let buffer = Vec::from(&bytes[security_buffer_offset..(security_buffer_offset + security_buffer_len)]);
        Some((Self { flags, security_mode, capabilities, previous_session_id, buffer }, &bytes[(security_buffer_offset + security_buffer_len)..]))
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBSessionSetupResponseBody {
    session_flags: SMBSessionFlags,
    buffer: Vec<u8>
}

impl SMBSessionSetupResponseBody {
    pub fn new(session_flags: SMBSessionFlags, buffer: Vec<u8>) -> Self {
        Self { session_flags, buffer }
    }

    pub fn from_request(request: SMBSessionSetupRequestBody, server_ctx: &mut ServerCtx) -> Option<Self> {
        Some(Self {
            session_flags: SMBSessionFlags::empty(),
            buffer: get_resp_buffer(server_ctx, &*request.buffer)?
        })
    }
}

impl SMBSessionSetupResponseBody {
    pub fn from_bytes(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < 9 { return None; }
        let security_buffer_offset = (bytes_to_u16(&bytes[4..6]) - 64) as usize;
        let security_buffer_len = bytes_to_u16(&bytes[6..8]) as usize;
        if bytes.len() < 9 + (security_buffer_len as usize) { return None }
        let session_flags = SMBSessionFlags::from_bits_truncate(bytes_to_u16(&bytes[2..4]));
        let buffer = Vec::from(&bytes[security_buffer_offset..(security_buffer_offset + security_buffer_len)]);
        Some((Self { session_flags, buffer }, &bytes[(security_buffer_offset + security_buffer_len)..]))
    }

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