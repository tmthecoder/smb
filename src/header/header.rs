use crate::header::{SMBCommandCode, SMBExtra, SMBFlags, SMBFlags2, SMBStatus};
use serde::{Serialize, Deserialize};
use crate::byte_helper::bytes_to_u16;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBHeader {
    command: SMBCommandCode,
    status: SMBStatus,
    flags: SMBFlags,
    flags2: SMBFlags2,
    extra: SMBExtra,
    tid: u16,
    pid: u16,
    uid: u16,
    mid: u16
}

impl SMBHeader {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 28 {
            return None;
        }
        Some(SMBHeader {
            command: bytes[0].try_into().ok()?,
            status: SMBStatus::from_bytes(&bytes[1..5])?,
            flags: SMBFlags::from_bits_truncate(bytes[5]),
            flags2: SMBFlags2::from_bits_truncate(bytes_to_u16(&bytes[6..8])),
            extra: SMBExtra::from_bytes(&bytes[8..20]),
            tid: bytes_to_u16(&bytes[20..22]),
            pid: bytes_to_u16(&bytes[22..24]),
            uid: bytes_to_u16(&bytes[24..26]),
            mid: bytes_to_u16(&bytes[26..28]),
        })
    }
}




