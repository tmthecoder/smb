use num_enum::TryFromPrimitive;
use serde::{Serialize, Deserialize};
use crate::byte_helper::{bytes_to_u16, u16_to_bytes};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum SMBStatus {
    NTStatus(NTStatusCode),
    DosError(char, char, u16)
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct NTStatusCode {
    level: NTStatusLevel,
    facility: [u8; 2],
    error_code: u16
}

#[repr(u8)]
#[derive(Serialize, Deserialize, TryFromPrimitive, PartialEq, Debug, Copy)]
pub enum NTStatusLevel {
    Success = 0x0,
    Information,
    Warning,
    Error
}

impl SMBStatus {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }
        let nibble = bytes[0] >> 4;
        if nibble == 0x0 || nibble == 0x4 || nibble == 0x8 || nibble == 0xC {
            let level = NTStatusLevel::try_from(bytes[0] >> 6).ok()?;
            let facility = [bytes[0] << 4, bytes[1]];
            let error_code = bytes_to_u16(&bytes[2..]);
            return Some(SMBStatus::NTStatus(NTStatusCode { level, facility, error_code }));
        }
        Some(SMBStatus::DosError(bytes[0].into(), bytes[2].into(), bytes_to_u16(&bytes[3..])))
    }
}

impl SMBStatus {
    pub(crate) fn as_bytes(&self) -> Vec<u8> {
        match self {
            SMBStatus::NTStatus(x) => vec![*x as u8 >> 4_u8],
            SMBStatus::DosError(c1, c2, code) => [
                &[*c1 as u8][0..],
                &[*c2 as u8][0..],
                &u16_to_bytes(*code)[0..]
            ].concat()
        }
    }
}