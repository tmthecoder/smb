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

    fn accept_security_context(&self, input_message: &NTLMMessage, output_token: &mut NTLMMessage) -> u8 {
        let msg = match input_message {
            NTLMMessage::Negotiate(x) => {
                x
            },
            NTLMMessage::Challenge(x) => {
                return 0;
            },
            NTLMMessage::Authenticate => {
                return 0;
            },
            NTLMMessage::Dummy => {
                return 0;
            }
        };

        fn add_if_present(flags: &mut NTLMNegotiateFlags, original: &NTLMNegotiateFlags, to_add: NTLMNegotiateFlags) {
            if original.contains(to_add) {
                flags.insert(to_add);
            }
        }

        fn add_if_else_present(flags: &mut NTLMNegotiateFlags, original: &NTLMNegotiateFlags, to_add: NTLMNegotiateFlags, fallback: NTLMNegotiateFlags) {
            if original.contains(to_add) {
                flags.insert(to_add);
            } else if original.contains(fallback) {
                flags.insert(fallback);
            }
        }
        let mut negotiate_flags = NTLMNegotiateFlags::TARGET_TYPE_SERVER
            | NTLMNegotiateFlags::TARGET_INFO | NTLMNegotiateFlags::TARGET_NAME_SUPPLOED
            | NTLMNegotiateFlags::VERSION | NTLMNegotiateFlags::NTLM_SESSION_SECURITY;

        add_if_else_present(&mut negotiate_flags, &msg.negotiate_flags, NTLMNegotiateFlags::UNICODE_ENCODING, NTLMNegotiateFlags::OEM_ENCODING);
        add_if_else_present(&mut negotiate_flags, &msg.negotiate_flags, NTLMNegotiateFlags::EXTENDED_SESSION_SECURITY, NTLMNegotiateFlags::LAN_MANAGER_SESSION_KEY);

        add_if_present(&mut negotiate_flags, &msg.negotiate_flags, NTLMNegotiateFlags::SIGN);
        add_if_present(&mut negotiate_flags, &msg.negotiate_flags, NTLMNegotiateFlags::SEAL);
        if msg.negotiate_flags.contains(NTLMNegotiateFlags::SIGN) || msg.negotiate_flags.contains(NTLMNegotiateFlags::SEAL) {
            add_if_present(&mut negotiate_flags, &msg.negotiate_flags, NTLMNegotiateFlags::USE_56_BIT_ENCRYPTION);
            add_if_present(&mut negotiate_flags, &msg.negotiate_flags, NTLMNegotiateFlags::USE_128_BIT_ENCRYPTION);
        }
        add_if_present(&mut negotiate_flags, &msg.negotiate_flags, NTLMNegotiateFlags::KEY_EXCHANGE);

        let target_name = "fakeserver";

        *output_token = NTLMMessage::Challenge(NTLMChallengeMessageBody::new(target_name.into(), negotiate_flags));

        0
    }
}