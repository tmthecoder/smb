use crate::body::{Capabilities, SecurityMode};
use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use crate::byte_helper::{bytes_to_u16, bytes_to_u32, bytes_to_u64};

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

bitflags! {
    #[derive(Serialize, Deserialize)]
    pub struct SMBSessionSetupFlags: u8 {
        const SMB2_SESSION_FLAG_BINDING = 0x01;
    }
}