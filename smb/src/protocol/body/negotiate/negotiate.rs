use std::marker::PhantomData;

use nom::bytes::complete::take;
use nom::combinator::{map, map_res};
use nom::IResult;
use nom::multi::count;
use nom::number::complete::{le_u16, le_u32};
use nom::sequence::tuple;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use smb_derive::{SMBByteSize, SMBFromBytes};

use crate::byte_helper::{u16_to_bytes, u32_to_bytes};
use crate::protocol::body::{Capabilities, FileTime, SMBDialect};
use crate::protocol::body::negotiate::{NegotiateContext, NegotiateSecurityMode};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBFromBytes, SMBByteSize)]
pub struct SMBNegotiateRequest {
    #[smb_direct(start = 4)]
    security_mode: NegotiateSecurityMode,
    #[smb_direct(start = 8)]
    capabilities: Capabilities,
    #[smb_direct(start = 12)]
    client_uuid: Uuid,
    #[smb_skip(start = 28, length = 8)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_vector(order = 1, count(start = 2, type = "u16"))]
    dialects: Vec<SMBDialect>,
    #[smb_vector(order = 2, align = 8, count(start = 32, type = "u16"))]
    negotiate_contexts: Vec<NegotiateContext>,
}

impl SMBNegotiateRequest {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (remaining, (_, dialect_count, security_mode, _, capabilities, client_uuid)) =
            tuple((
                map(le_u16, |x| x == 36),
                le_u16,
                map(le_u16, NegotiateSecurityMode::from_bits_truncate),
                take(2_usize),
                map(le_u32, Capabilities::from_bits_truncate),
                map_res(take(16_usize), Uuid::from_slice),
            ))(bytes)?;
        let dialect_start = &remaining[8..];
        let (remaining_post_dialect, dialects) = count(
            map_res(le_u16, SMBDialect::try_from),
            dialect_count as usize,
        )(dialect_start)?;
        let (remaining_bytes, negotiate_contexts) = if dialects.contains(&SMBDialect::V3_1_1) {
            let (remaining_post_context, contexts) =
                tuple((le_u32, le_u16, take(2_usize)))(remaining)
                    .and_then(|(_, (_, neg_ctx_cnt, _))| {
                        let padding = (dialect_start.len() - remaining_post_dialect.len()) % 8;
                        count(NegotiateContext::parse, neg_ctx_cnt as usize)(
                            &remaining_post_dialect[padding..],
                        )
                    })
                    .unwrap();
            (remaining_post_context, contexts)
        } else {
            (remaining_post_dialect, Vec::new())
        };
        Ok((
            remaining_bytes,
            Self {
                security_mode,
                capabilities,
                client_uuid,
                dialects,
                negotiate_contexts,
                reserved: PhantomData
            },
        ))
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct SMBNegotiateResponseBody {
    security_mode: NegotiateSecurityMode,
    dialect: SMBDialect,
    guid: Uuid,
    capabilities: Capabilities,
    max_transact_size: u32,
    max_read_size: u32,
    max_write_size: u32,
    system_time: FileTime,
    server_start_time: FileTime,
    buffer: Vec<u8>,
    negotiate_contexts: Vec<NegotiateContext>,
}

impl SMBNegotiateResponseBody {
    pub fn new(
        security_mode: NegotiateSecurityMode,
        dialect: SMBDialect,
        capabilities: Capabilities,
        max_transact_size: u32,
        max_read_size: u32,
        max_write_size: u32,
        server_start_time: FileTime,
        buffer: Vec<u8>,
    ) -> Self {
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
            buffer,
            negotiate_contexts: Vec::new(),
        }
    }

    pub fn from_request(request: SMBNegotiateRequest, token: Vec<u8>) -> Option<Self> {
        let mut dialects = request.dialects.clone();
        dialects.sort();
        let mut negotiate_contexts = Vec::new();
        let dialect = *dialects.last()?;
        if dialect == SMBDialect::V3_1_1 {
            for neg_ctx in request.negotiate_contexts {
                negotiate_contexts.push(neg_ctx.response_from_existing()?);
            }
        }
        Some(Self {
            security_mode: request.security_mode | NegotiateSecurityMode::NEGOTIATE_SIGNING_REQUIRED,
            dialect: *dialects.last()?,
            guid: Uuid::new_v4(),
            capabilities: request.capabilities,
            max_transact_size: 65535,
            max_read_size: 65535,
            max_write_size: 65535,
            system_time: FileTime::now(),
            server_start_time: FileTime::from_unix(0),
            buffer: token,
            negotiate_contexts,
        })
    }
}

impl SMBNegotiateResponseBody {
    pub fn as_bytes(&self) -> Vec<u8> {
        let len_w_buffer = 128 + self.buffer.len();
        let padding_len = 8 - (len_w_buffer % 8);
        let padding = vec![0; padding_len];
        let mut negotiate_offset = 0;
        let mut negotiate_ctx_vec = Vec::new();
        if self.dialect == SMBDialect::V3_1_1 {
            negotiate_offset = len_w_buffer + padding_len;
            for (idx, ctx) in self.negotiate_contexts.iter().enumerate() {
                let mut bytes = ctx.as_bytes();
                if idx != self.negotiate_contexts.len() - 1 {
                    let needed_extra = 8 - (bytes.len() % 8);
                    bytes.append(&mut vec![0; needed_extra]);
                }
                negotiate_ctx_vec.append(&mut bytes);
            }
        }
        let security_offset = if self.buffer.is_empty() {
            [0, 0]
        } else {
            [128, 0]
        };
        [
            &[65, 0][0..], // Structure Size
            &u16_to_bytes(self.security_mode.bits()),
            &u16_to_bytes(self.dialect as u16),
            &u16_to_bytes(self.negotiate_contexts.len() as u16),
            self.guid.as_bytes(),
            &u32_to_bytes(self.capabilities.bits() as u32),
            &u32_to_bytes(self.max_transact_size),
            &u32_to_bytes(self.max_read_size),
            &u32_to_bytes(self.max_write_size),
            &*self.system_time.as_bytes(),
            &*self.server_start_time.as_bytes(),
            &security_offset, // Security Buffer Offset
            &u16_to_bytes(self.buffer.len() as u16),
            &u32_to_bytes(negotiate_offset as u32),
            &*self.buffer,
            &*padding,
            &*negotiate_ctx_vec,
        ]
        .concat()
    }
}
