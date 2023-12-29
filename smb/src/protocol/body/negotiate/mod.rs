use std::any::Any;
use std::collections::HashSet;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use smb_core::error::SMBError;
use smb_core::SMBResult;
use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::{Capabilities, FileTime, SMBDialect};
use crate::protocol::body::negotiate::context::NegotiateContext;
use crate::protocol::body::negotiate::security_mode::NegotiateSecurityMode;
use crate::server::connection::{SMBConnection, SMBConnectionUpdate};
use crate::server::Server;
use crate::socket::message_stream::{SMBReadStream, SMBWriteStream};
use crate::util::auth::AuthProvider;
use crate::util::auth::spnego::{SPNEGOToken, SPNEGOTokenInitBody};

pub mod context;
pub mod security_mode;

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

impl SMBNegotiateRequest {
    pub fn validate_and_set_state<R: SMBReadStream, W: SMBWriteStream, S: Server>(&self, connection: &SMBConnection<R, W, S>, server: &S) -> SMBResult<(SMBConnectionUpdate<R, W, S>, HashSet<u16>)> {
        if connection.negotiate_dialect() != SMBDialect::default() {
            return Err(SMBError::response_error("Invalid request received"));
        }
        let mut update = SMBConnectionUpdate::default();
        let mut received_ctxs = HashSet::new();
        for context in self.negotiate_contexts.iter() {
            let (change, actual) = context.validate_and_set_state(update, server)?;
            update = change;
            if actual {
                received_ctxs.insert(context.byte_code());
            }
        }
        let mut dialects = Vec::new();
        for dialect in self.dialects.iter() {
            if *dialect != SMBDialect::V2_X_X {
                dialects.push(*dialect)
            }
        }
        dialects.sort();

        let mut security_mode = NegotiateSecurityMode::NEGOTIATE_SIGNING_ENABLED;
        if server.require_message_signing() {
            security_mode |= NegotiateSecurityMode::NEGOTIATE_SIGNING_REQUIRED;
        }

        let mut capabilities = Capabilities::empty();
        if connection.supports_multi_credit() {
            capabilities |= Capabilities::LARGE_MTU;
        }
        if connection.dialect() as u16 > 0x300 {
            if server.multi_channel_capable() {
                capabilities |= Capabilities::MULTI_CHANNEL;
            }
            if self.capabilities.contains(Capabilities::PERSISTENT_HANDLES) {
                capabilities |= Capabilities::PERSISTENT_HANDLES;
            }
            if connection.dialect() != SMBDialect::V3_1_1 && server.encryption_supported() && capabilities.contains(Capabilities::ENCRYPTION) {
                capabilities |= Capabilities::ENCRYPTION;
            }
        }

        update = update
            .dialect(*dialects.last()
                .ok_or(SMBError::response_error("No Dialects Present"))?)
            .client_dialects(dialects)
            .client_capabilities(self.capabilities)
            .client_guid(self.client_uuid)
            .should_sign(self.security_mode.contains(NegotiateSecurityMode::NEGOTIATE_SIGNING_REQUIRED))
            .server_capabilites(capabilities)
            .server_security_mode(security_mode);
        Ok((update, received_ctxs))
    }
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

    pub fn from_connection_state<A: AuthProvider, R: SMBReadStream, W: SMBWriteStream, S: Server>(connection: &SMBConnection<R, W, S>, server: &S, negotiate_contexts: HashSet<u16>) -> Self {
        let buffer = SPNEGOToken::Init(SPNEGOTokenInitBody::<A>::new()).as_bytes(true);
        let negotiate_contexts = NegotiateContext::from_connection_state(connection, negotiate_contexts);
        Self {
            security_mode: connection.server_security_mode(),
            dialect: connection.dialect(),
            // TODO make this server guid
            guid: server.guid(),
            capabilities: connection.server_capabilities(),
            max_transact_size: connection.max_transact_size(),
            max_read_size: connection.max_read_size(),
            max_write_size: connection.max_write_size(),
            system_time: FileTime::now(),
            server_start_time: FileTime::default(),
            buffer,
            negotiate_contexts,
        }
    }
}