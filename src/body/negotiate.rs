use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};
use crate::byte_helper::bytes_to_u16;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBNegotiationBody {
    dialects: Vec<SMBDialect>,
}

impl SMBNegotiationBody {
    pub fn from_bytes(bytes: &[u8]) -> (Self, &[u8]) {
        let dialect_count = bytes_to_u16(&bytes[2..4]) as usize;
        let mut dialects = Vec::new();
        let mut dialect_idx = 36;
        while dialects.len() < dialect_count {
            let dialect_code = bytes_to_u16(&bytes[dialect_idx..(dialect_idx+2)]);
            if let Ok(dialect) = SMBDialect::try_from(dialect_code) {
                dialects.push(dialect);
            }
            dialect_idx += 2;
        }
        (Self { dialects }, &bytes[dialect_idx..])
    }
}

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize)]
pub enum SMBDialect {
    V2_0_2 = 0x202,
    V2_1_0 = 0x210,
    V3_0_0 = 0x300,
    V3_0_2 = 0x302,
    V3_1_1 = 0x311
}