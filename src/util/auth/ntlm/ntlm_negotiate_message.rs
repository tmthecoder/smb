use crate::byte_helper::bytes_to_u32;
use crate::util::auth::ntlm::ntlm_message::NTLMNegotiateFlags;
use serde::{Deserialize, Serialize};
use crate::util::auth::ntlm::NTLMChallengeMessageBody;

#[derive(Debug, Deserialize, Serialize)]
pub struct NTLMNegotiateMessageBody {
    signature: String,
    pub negotiate_flags: NTLMNegotiateFlags,
    domain_name: String,
    workstation: String,
}

impl NTLMNegotiateMessageBody {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 24 { return None;}
        let signature = String::from_utf8(bytes[..8].to_vec()).ok()?;
        let negotiate_flags = NTLMNegotiateFlags::from_bits(bytes_to_u32(&bytes[12..16])).unwrap();
        let domain_name = String::from_utf8(bytes[16..24].to_vec()).ok()?;
        let workstation = String::from_utf8(bytes[24..32].to_vec()).ok()?;
        Some(Self {
            signature,
            negotiate_flags,
            domain_name,
            workstation,
        })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        [
            self.signature.as_bytes(),

        ].concat()
    }
}

impl NTLMNegotiateMessageBody {
    pub fn get_challenge_response(&self) -> NTLMChallengeMessageBody {
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

        add_if_else_present(&mut negotiate_flags, &self.negotiate_flags, NTLMNegotiateFlags::UNICODE_ENCODING, NTLMNegotiateFlags::OEM_ENCODING);
        add_if_else_present(&mut negotiate_flags, &self.negotiate_flags, NTLMNegotiateFlags::EXTENDED_SESSION_SECURITY, NTLMNegotiateFlags::LAN_MANAGER_SESSION_KEY);

        add_if_present(&mut negotiate_flags, &self.negotiate_flags, NTLMNegotiateFlags::SIGN);
        add_if_present(&mut negotiate_flags, &self.negotiate_flags, NTLMNegotiateFlags::SEAL);
        if self.negotiate_flags.contains(NTLMNegotiateFlags::SIGN) || self.negotiate_flags.contains(NTLMNegotiateFlags::SEAL) {
            add_if_present(&mut negotiate_flags, &self.negotiate_flags, NTLMNegotiateFlags::USE_56_BIT_ENCRYPTION);
            add_if_present(&mut negotiate_flags, &self.negotiate_flags, NTLMNegotiateFlags::USE_128_BIT_ENCRYPTION);
        }
        add_if_present(&mut negotiate_flags, &self.negotiate_flags, NTLMNegotiateFlags::KEY_EXCHANGE);

        let target_name = "fakeserver";

        NTLMChallengeMessageBody::new(target_name.into(), negotiate_flags)

    }
}