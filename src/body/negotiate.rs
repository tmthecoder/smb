use std::io::Bytes;
use std::ops::Neg;
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::body::{Capabilities, FileTime, SecurityMode};
use crate::byte_helper::{bytes_to_u16, bytes_to_u32, u16_to_bytes, u32_to_bytes};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBNegotiationRequestBody {
    security_mode: SecurityMode,
    capabilities: Capabilities,
    client_uuid: Uuid,
    dialects: Vec<SMBDialect>,
    // negotiate_contexts: Vec
}

impl SMBNegotiationRequestBody {
    pub fn from_bytes(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < 37 { return None }
        let dialect_count = bytes_to_u16(&bytes[2..4]) as usize;
        let security_mode = SecurityMode::from_bits_truncate(bytes[4]);
        let capabilities = Capabilities::from_bits_truncate(bytes[8]);
        let client_uuid = Uuid::from_slice(&bytes[12..28]).ok()?;
        let mut dialects = Vec::new();
        let mut dialect_idx = 36;
        let mut carryover = bytes;
        while dialects.len() < dialect_count {
            let dialect_code = bytes_to_u16(&bytes[dialect_idx..(dialect_idx+2)]);
            if let Ok(dialect) = SMBDialect::try_from(dialect_code) {
                dialects.push(dialect);
            }
            dialect_idx += 2;
        }
        carryover = &bytes[dialect_idx..];
        if dialects.contains(&SMBDialect::V3_1_1) {
            let negotiate_ctx_idx = bytes_to_u32(&bytes[28..32]) - 64;
            let negotiate_ctx_cnt = bytes_to_u16(&bytes[32..34]);
            println!("Negotiate idx: {}, cnt: {}", negotiate_ctx_idx, negotiate_ctx_cnt);
            let mut added_ctxs = 0;
            let mut start = negotiate_ctx_idx as usize;
            println!("All bytes: {:?}", bytes);
            while added_ctxs < negotiate_ctx_cnt {
                println!("CTX Bytes: {:?}", &bytes[start..]);
                println!("Context type num: {}", bytes_to_u16(&bytes[start..(start+2)]));
                let context_type = NegotiateContext::from_bytes(&bytes[start..])?;
                println!("Context: {:?}", context_type);
                let context_len = bytes_to_u16(&bytes[(start+2)..(start+4)]);
                println!("context type: {:?}, len: {}", context_type, context_len);
                added_ctxs += 1;
                start += context_len as usize;
                start += 8;
                if added_ctxs != negotiate_ctx_cnt {
                    start += 8 - (start % 8);
                    println!("new start: {}", start);
                }
            }
            if start < bytes.len() {
                carryover = &bytes[start..];
            } else {
                carryover = &[];
            }
            // TODO add negotiate ctx parsing
        }
        Some((Self { security_mode, capabilities, client_uuid, dialects }, carryover))
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBNegotiationResponseBody {
    security_mode: SecurityMode,
    dialect: SMBDialect,
    guid: Uuid,
    capabilities: Capabilities,
    max_transact_size: u32,
    max_read_size: u32,
    max_write_size: u32,
    system_time: FileTime,
    server_start_time: FileTime,
    buffer: Vec<u8>
}

impl SMBNegotiationResponseBody {
    pub fn new(security_mode: SecurityMode, dialect: SMBDialect, capabilities: Capabilities, max_transact_size: u32, max_read_size: u32, max_write_size: u32, server_start_time: FileTime, buffer: Vec<u8>) -> Self {
        Self {
            security_mode,
            dialect,
            guid: Uuid::new_v4(),
            capabilities,
            max_transact_size,
            max_read_size,
            max_write_size,
            system_time: FileTime::now(),
            server_start_time,
            buffer
        }
    }
}

impl SMBNegotiationResponseBody {
    pub fn as_bytes(&self) -> Vec<u8> {
        [
            &[65, 0][0..], // Structure Size
            &[self.security_mode.bits(), 0],
            &u16_to_bytes(self.dialect as u16),
            &*self.guid.as_bytes(),
            &u32_to_bytes(self.capabilities.bits() as u32),
            &u32_to_bytes(self.max_transact_size),
            &u32_to_bytes(self.max_read_size),
            &u32_to_bytes(self.max_write_size),
            &*self.system_time.as_bytes(),
            &*self.server_start_time.as_bytes(),
            &[64, 0], // Security Buffer Offset
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
    V3_1_1 = 0x311,
    V2_X_X = 0x2FF
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PreAuthIntegrityCapabilitiesBody {
    hash_algorithms: Vec<HashAlgorithm>,
    salt: Vec<u8>,
}

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize)]
enum HashAlgorithm {
    SHA512 = 0x01
}

impl PreAuthIntegrityCapabilitiesBody {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let algorithm_cnt = bytes_to_u16(&bytes[0..2]);
        let salt_len = bytes_to_u16(&bytes[2..4]) as usize;
        let mut bytes_ptr = 4_usize;
        let mut hash_algorithms = Vec::new();
        while hash_algorithms.len() < algorithm_cnt as usize {
            hash_algorithms.push(HashAlgorithm::try_from(bytes_to_u16(&bytes[bytes_ptr..(bytes_ptr+2)])).ok()?);
            bytes_ptr += 2;
        }
        let salt = Vec::from(&bytes[bytes_ptr..(bytes_ptr + salt_len)]);
        Some(Self { hash_algorithms, salt })
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NegotiateContext {
    PreAuthIntegrityCapabilities(PreAuthIntegrityCapabilitiesBody),
    EncryptionCapabilities(),
    CompressionCapabilities(),
    NetnameNegotiateContextID(),
    TransportCapabilities(),
    RDMATransformCapabilities(),
    SigningCapabilities()
}

impl NegotiateContext {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let ctx_type_num = bytes_to_u16(&bytes[0..2]);
        println!("Num: {}", ctx_type_num);
        match ctx_type_num {
            0x01 => Some(Self::PreAuthIntegrityCapabilities(PreAuthIntegrityCapabilitiesBody::from_bytes(&bytes[8..])?)),
            0x02 => Some(Self::EncryptionCapabilities()),
            0x03 => Some(Self::CompressionCapabilities()),
            0x05 => Some(Self::NetnameNegotiateContextID()),
            0x06 => Some(Self::TransportCapabilities()),
            0x07 => Some(Self::RDMATransformCapabilities()),
            0x08 => Some(Self::SigningCapabilities()),
            _ => None
        }
    }
}