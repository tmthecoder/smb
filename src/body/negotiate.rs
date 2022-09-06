use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};
use crate::body::{Capabilities, FileTime, SecurityMode};
use crate::byte_helper::{bytes_to_u16, u16_to_bytes, u32_to_bytes};

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

impl SMBNegotiationResponseBody {
    pub fn as_bytes(&self) -> Vec<u8> {
        [
            &[0, 65][0..], // Structure Size
            &[0, self.security_mode.bits()],
            &u16_to_bytes(self.dialect as u16),
            &self.guid,
            &u32_to_bytes(self.capabilities.bits() as u32),
            &u32_to_bytes(self.max_transact_size),
            &u32_to_bytes(self.max_read_size),
            &u32_to_bytes(self.max_write_size),
            &*self.system_time.as_bytes(),
            &*self.server_start_time.as_bytes(),
            &[0, 64], // Security Buffer Offset
            &u16_to_bytes(self.buffer.len() as u16),
            &[0; 4], // NegotiateContextOffset/Reserved/TODO
            &*self.buffer
            // TODO padding & NegotiateContextList
        ].concat()
    }
}

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Copy, Clone)]
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