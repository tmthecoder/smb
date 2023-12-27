use std::marker::PhantomData;

use nom::multi::count;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::{Capabilities, FileTime, SMBDialect};
use crate::protocol::body::negotiate::{NegotiateContext, NegotiateSecurityMode};
use crate::server::SMBConnection;
use crate::socket::message_stream::{SMBReadStream, SMBWriteStream};
use crate::util::auth::AuthProvider;
use crate::util::auth::spnego::{SPNEGOToken, SPNEGOTokenInitBody};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBFromBytes, SMBByteSize, SMBToBytes)]
#[smb_byte_tag(value = 36)]
pub struct SMBNegotiateRequest {
    #[smb_direct(start(fixed = 4))]
    pub(crate) security_mode: NegotiateSecurityMode,
    #[smb_direct(start(fixed = 8))]
    pub(crate) capabilities: Capabilities,
    #[smb_direct(start(fixed = 12))]
    pub(crate) client_uuid: Uuid,
    #[smb_skip(start = 28, length = 8)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_vector(order = 1, count(inner(start = 2, num_type = "u16")))]
    pub(crate) dialects: Vec<SMBDialect>,
    #[smb_vector(order = 2, align = 8, count(inner(start = 32, num_type = "u16")), offset(inner(start = 28, num_type = "u32", subtract = 64)))]
    negotiate_contexts: Vec<NegotiateContext>,
}
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBToBytes, SMBByteSize, SMBFromBytes)]
#[smb_byte_tag(value = 65)]
pub struct SMBNegotiateResponse {
    #[smb_direct(start(fixed = 2))]
    security_mode: NegotiateSecurityMode,
    #[smb_direct(start(fixed = 4))]
    dialect: SMBDialect,
    #[smb_direct(start(fixed = 8))]
    guid: Uuid,
    #[smb_direct(start(fixed = 24))]
    capabilities: Capabilities,
    #[smb_direct(start(fixed = 28))]
    max_transact_size: u32,
    #[smb_direct(start(fixed = 32))]
    max_read_size: u32,
    #[smb_direct(start(fixed = 36))]
    max_write_size: u32,
    #[smb_direct(start(fixed = 40))]
    system_time: FileTime,
    #[smb_direct(start(fixed = 48))]
    server_start_time: FileTime,
    #[smb_buffer(offset(inner(start = 56, num_type = "u16", subtract = 64, min_val = 128)), length(inner(start = 58, num_type = "u16")), order = 1)]
    buffer: Vec<u8>,
    #[smb_vector(order = 2, align = 8, count(inner(start = 6, num_type = "u16")), offset(inner(start = 60, num_type = "u32", subtract = 64)))]
    negotiate_contexts: Vec<NegotiateContext>,
}

impl SMBNegotiateResponse {
    pub fn legacy_response() -> Self {
        Self {
            security_mode: NegotiateSecurityMode::empty(),
            dialect: SMBDialect::V2_X_X,
            guid: Uuid::new_v4(),
            capabilities: Capabilities::empty(),
            max_transact_size: 100,
            max_read_size: 100,
            max_write_size: 100,
            system_time: FileTime::now(),
            server_start_time: FileTime::default(),
            buffer: vec![],
            negotiate_contexts: Vec::new(),
        }
    }

    pub fn from_connection_state<A: AuthProvider, R: SMBReadStream, W: SMBWriteStream>(connection: &SMBConnection<R, W>) -> Self {
        let buffer = SPNEGOToken::Init(SPNEGOTokenInitBody::<A>::new()).as_bytes(true);
        let negotiate_contexts = NegotiateContext::from_connection_state(connection);
        Self {
            security_mode: connection.server_security_mode,
            dialect: connection.dialect,
            // TODO make this server guid
            guid: Uuid::new_v4(),
            capabilities: connection.server_capabilites,
            max_transact_size: connection.max_transact_size,
            max_read_size: connection.max_read_size,
            max_write_size: connection.max_write_size,
            system_time: FileTime::now(),
            server_start_time: FileTime::default(),
            buffer,
            negotiate_contexts,
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