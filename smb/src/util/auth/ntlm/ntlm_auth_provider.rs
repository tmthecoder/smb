use serde::{Deserialize, Serialize};

use smb_core::error::SMBError;
use smb_core::nt_status::NTStatus;
use smb_core::SMBResult;

use crate::util::auth::{AuthContext, AuthProvider};
use crate::util::auth::ntlm::ntlm_message::NTLMMessage;
use crate::util::auth::user::User;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NTLMAuthProvider {
    accepted_users: Vec<User>,
    guest_supported: bool
}

impl NTLMAuthProvider {
    pub fn new(accepted_users: Vec<User>, guest_supported: bool) -> Self {
        Self {
            accepted_users,
            guest_supported
        }
    }
}

impl AuthProvider for NTLMAuthProvider {
    type Message = NTLMMessage;
    type Context = NTLMAuthContext;

    fn get_oid() -> Vec<u8> {
        vec![0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a]
    }

    fn accept_security_context(&self, input_message: &NTLMMessage, context: &mut NTLMAuthContext) -> (NTStatus, NTLMMessage) {
        match input_message {
            NTLMMessage::Negotiate(x) => {
                let (status, challenge) = x.get_challenge_response();
                context.server_challenge = (*challenge.server_challenge()).into();
                (status, NTLMMessage::Challenge(challenge))
            },
            NTLMMessage::Challenge(x) => {
                (NTStatus::StatusSuccess, NTLMMessage::Dummy)
            },
            NTLMMessage::Authenticate(x) => {
                let auth_status = x.authenticate(context, &self.accepted_users, self.guest_supported);
                if auth_status == 0 {
                    (NTStatus::StatusSuccess, NTLMMessage::Dummy)
                } else {
                    (NTStatus::LogonFailure, NTLMMessage::Dummy)
                }
            },
            NTLMMessage::Dummy => {
                (NTStatus::StatusSuccess, NTLMMessage::Dummy)
            }
        }
    }
}

#[derive(Debug)]
pub struct NTLMAuthContext {
    pub(crate) domain_name: Option<String>,
    pub(crate) user_name: Option<String>,
    pub(crate) work_station: Option<String>,
    pub(crate) version: Option<String>,
    pub(crate) guest: Option<bool>,
    pub(crate) session_key: Vec<u8>,
    pub(crate) server_challenge: Vec<u8>,
}

impl NTLMAuthContext {
    pub fn new() -> Self {
        Self {
            domain_name: None,
            user_name: None,
            work_station: None,
            version: None,
            guest: None,
            session_key: Vec::new(),
            server_challenge: Vec::new(),
        }
    }
}

impl Default for NTLMAuthContext {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthContext for NTLMAuthContext {
    type UserName = String;

    fn init() -> Self {
        Self::new()
    }

    fn session_key(&self) -> &[u8] {
        &self.session_key
    }

    fn user_name(&self) -> SMBResult<&Self::UserName> {
        self.user_name.as_ref().ok_or(SMBError::server_error("No user name"))
    }
}