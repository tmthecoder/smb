use crate::header::{SMBCommandCode, SMBExtra, SMBFlags, SMBFlags2, SMBStatus};
use serde::{Serialize, Deserialize};
use crate::header::status::NTStatusLevel;

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
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 28 {
            return None;
        }
        Some(SMBHeader {
            command: bytes[0].try_into().unwrap(),
            status: SMBStatus::NTStatus(NTStatusLevel::Success),
            flags: SMBFlags::from_bits_truncate(bytes[5]),
            flags2: SMBFlags2::from_bits_truncate(((bytes[6] as u16) << 2) + bytes[7] as u16),
            extra: SMBExtra::from_slice(&bytes[8..20]),
            tid: ((bytes[20] as u16) << 2) + bytes[21] as u16,
            pid: ((bytes[22] as u16) << 2) + bytes[23] as u16,
            uid: ((bytes[24] as u16) << 2) + bytes[25] as u16,
            mid: ((bytes[26] as u16) << 2) + bytes[27] as u16,
        })
    }
}





