use serde::{Deserialize, Serialize};

use smb_core::error::SMBError;
use smb_core::nt_status::NTStatus;
use smb_core::SMBResult;
use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::capabilities::Capabilities;
use crate::protocol::body::session_setup::flags::{SMBSessionFlags, SMBSessionSetupFlags};
use crate::protocol::body::session_setup::security_mode::SessionSetupSecurityMode;
use crate::protocol::header::SMBSyncHeader;
use crate::server::connection::{SMBConnection, SMBConnectionUpdate};
use crate::server::Server;
use crate::socket::message_stream::{SMBReadStream, SMBWriteStream};

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
    pub fn get_buffer_copy(&self) -> Vec<u8> {
        self.buffer.clone()
    }
    pub fn validate_and_set_state<R: SMBReadStream, W: SMBWriteStream, S: Server>(&self, connection: &SMBConnection<R, W, S>, server: &S, header: &SMBSyncHeader) -> SMBResult<SMBConnectionUpdate<R, W, S>> {
        if server.encrypt_data() && (!server.unencrypted_access()
            && (connection.dialect() as u16 <= 0x300
            || !connection.client_capabilities().contains(Capabilities::ENCRYPTION))) {
            return Err(SMBError::response_error(NTStatus::AccessDenied));
        }

        // if header.sess

        Err(SMBError::response_error(NTStatus::AccessDenied))
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

    pub fn from_request(request: SMBSessionSetupRequest, token: Vec<u8>) -> Option<Self> {
        Some(Self {
            session_flags: SMBSessionFlags::empty(),
            buffer: token,
        })
    }
}