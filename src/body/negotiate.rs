use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};
use crate::body::{Capabilities, FileTime, SecurityMode};
use crate::byte_helper::bytes_to_u16;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBNegotiationRequestBody {
    dialects: Vec<SMBDialect>,
    // negotiate_contexts: Vec
}

impl SMBNegotiationRequestBody {
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

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBNegotiationResponseBody {
    security_mode: SecurityMode,
    dialect: SMBDialect,
    guid: [u8; 16],
    capabilities: Capabilities,
    max_transact_size: u32,
    max_read_size: u32,
    max_write_size: u32,
    system_time: FileTime,
    server_start_time: FileTime,
    buffer: Vec<u8>
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

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize)]
pub enum NegotiateContext {
    PreAuthIntegrityCapabilities = 0x01,
    EncryptionCapabilities,
    CompressionCapabilities,
    NetnameNegotiateContextID = 0x05,
    TransportCapabilities,
    RDMATransformCapabilities,
    SigningCapabilities
}