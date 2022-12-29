use serde::{Deserialize, Serialize};
use crate::util::auth::{AuthProvider, User};
use crate::util::auth::ntlm::ntlm_message::NTLMNegotiateFlags;
use crate::util::auth::ntlm::{NTLMChallengeMessageBody, NTLMMessage};

#[derive(Serialize, Deserialize, Debug)]
pub struct NTLMAuthProvider {
    accepted_users: Vec<User>
}

impl NTLMAuthProvider {
    pub fn new(accepted_users: Vec<User>) -> Self {
        Self {
            accepted_users
        }
    }
}

impl AuthProvider for NTLMAuthProvider {
    type Item = NTLMMessage;

    fn get_oid() -> Vec<u8> {
        vec![0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a]
    }

    fn accept_security_context(&self, input_message: &NTLMMessage) -> (u8, NTLMMessage) {
        match input_message {
            NTLMMessage::Negotiate(x) => {
                (0, NTLMMessage::Challenge(x.get_challenge_response()))
            },
            NTLMMessage::Challenge(x) => {
                (0, NTLMMessage::Dummy)
            },
            NTLMMessage::Authenticate(x) => {
                (0, NTLMMessage::Dummy)
            },
            NTLMMessage::Dummy => {
                (0, NTLMMessage::Dummy)
            }
        }
    }
}