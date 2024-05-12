use std::collections::HashMap;

use digest::Digest;
use serde::{Deserialize, Serialize};
use sha2::Sha512;

use smb_core::{SMBResult, SMBToBytes};
use smb_core::error::SMBError;
use smb_core::nt_status::NTStatus;
use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::capabilities::Capabilities;
use crate::protocol::body::dialect::SMBDialect;
use crate::protocol::body::session_setup::flags::{SMBSessionFlags, SMBSessionSetupFlags};
use crate::protocol::body::session_setup::security_mode::SessionSetupSecurityMode;
use crate::protocol::header::flags::SMBFlags;
use crate::protocol::header::SMBSyncHeader;
use crate::server::connection::{Connection, SMBConnection, SMBConnectionUpdate};
use crate::server::preauth_session::SMBPreauthSession;
use crate::server::Server;
use crate::server::session::{Session, SessionState};
use crate::socket::message_stream::{SMBReadStream, SMBWriteStream};
use crate::util::auth::AuthProvider;

pub mod security_mode;
pub mod flags;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBFromBytes, SMBByteSize, SMBToBytes)]
#[smb_byte_tag(value = 25)]
pub struct SMBSessionSetupRequest {
    #[smb_direct(start(fixed = 2))]
    flags: SMBSessionSetupFlags,
    #[smb_direct(start(fixed = 3))]
    security_mode: SessionSetupSecurityMode,
    #[smb_direct(start(fixed = 4))]
    capabilities: Capabilities,
    #[smb_direct(start(fixed = 16))]
    previous_session_id: u64,
    #[smb_buffer(offset(inner(start = 12, num_type = "u16", subtract = 64)), length(inner(start = 14, num_type = "u16")))]
    buffer: Vec<u8>,
}

impl SMBSessionSetupRequest {
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }
    pub fn flags(&self) -> SMBSessionSetupFlags {
        self.flags
    }
    pub async fn validate_and_set_state<R: SMBReadStream, W: SMBWriteStream, S: Server<ConnectionType=SMBConnection<R, W, S>>>(&self, connection: &SMBConnection<R, W, S>, server: &S, session: &S::SessionType, header: &SMBSyncHeader) -> SMBResult<SMBConnectionUpdate<R, W, S>> {
        let mut update = SMBConnectionUpdate::default();
        if server.encrypt_data() && (!server.unencrypted_access()
            && (connection.dialect().is_smb3()
            || !connection.client_capabilities().contains(Capabilities::ENCRYPTION))) {
            return Err(SMBError::response_error(NTStatus::AccessDenied));
        }

        if connection.dialect().is_smb3() && server.multi_channel_capable() && self.flags.contains(SMBSessionSetupFlags::BINDING) {
            let locked_conn = session.connection_res()?;
            let session_conn = locked_conn.read().await;
            if session_conn.dialect() != connection.dialect() ||
                header.flags.contains(SMBFlags::SIGNED) {
                return Err(SMBError::response_error(NTStatus::InvalidParameter));
            }
            if session_conn.client_guid() != connection.client_guid() {
                return Err(SMBError::response_error(NTStatus::UserSessionDeleted));
            }
            if session.state() == SessionState::InProgress {
                return Err(SMBError::response_error(NTStatus::RequestNotAccepted));
            }

            if session.state() == SessionState::Expired {
                return Err(SMBError::response_error(NTStatus::NetworkSessionExpired))
            }

            if session.anonymous() || session.guest() {
                return Err(SMBError::response_error(NTStatus::NotSupported));
            }
            if connection.dialect() == SMBDialect::V3_1_1 && !connection.preauth_sessions().contains_key(&session.id()) {
                let mut sha = Sha512::default();
                sha.update(connection.preauth_integtiry_hash_value());
                sha.update(&self.smb_to_bytes());
                let bytes = sha.finalize().to_vec();
                let preauth_session = SMBPreauthSession::new(session.id(), bytes);
                update = update.preauth_session_table(HashMap::from([(session.id(), preauth_session)]));
            }
        }
        Ok(update)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBToBytes, SMBFromBytes, SMBByteSize)]
#[smb_byte_tag(value = 9)]
pub struct SMBSessionSetupResponse {
    #[smb_direct(start(fixed = 2))]
    session_flags: SMBSessionFlags,
    #[smb_buffer(offset(inner(start = 4, num_type = "u16", subtract = 64, min_val = 72)), length(inner(start = 6, num_type = "u16")))]
    buffer: Vec<u8>,
}

impl SMBSessionSetupResponse {
    pub fn new(session_flags: SMBSessionFlags, buffer: Vec<u8>) -> Self {
        Self {
            session_flags,
            buffer,
        }
    }

    pub fn from_session_state<S: Server>(session: &S::SessionType, buffer: Vec<u8>) -> Self {
        let mut session_flags = SMBSessionFlags::empty();
        if session.guest() {
            session_flags |= SMBSessionFlags::IS_GUEST;
        }
        if session.anonymous() {
            session_flags |= SMBSessionFlags::IS_NULL;
        }
        if session.encrypt_data() {
            session_flags |= SMBSessionFlags::ENCRYPT_DATA;
        }
        Self {
            session_flags,
            buffer,
        }
    }

    pub fn from_request(request: SMBSessionSetupRequest, token: Vec<u8>) -> Option<Self> {
        Some(Self {
            session_flags: SMBSessionFlags::empty(),
            buffer: token,
        })
    }
}