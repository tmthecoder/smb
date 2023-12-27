use serde::{Deserialize, Serialize};

use crate::util::auth::{AuthContext, AuthProvider, User};
use crate::util::auth::nt_status::NTStatus;
use crate::util::auth::ntlm::NTLMMessage;

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
                    (NTStatus::StatusLogonFailure, NTLMMessage::Dummy)
                }
            },
            NTLMMessage::Dummy => {
                (NTStatus::StatusSuccess, NTLMMessage::Dummy)
            }
        }
    }
}

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
    fn init() -> Self {
        Self::new()
    }
}