use crate::byte_helper::bytes_to_u32;
use crate::util::auth::ntlm::ntlm_message::NTLMNegotiateFlags;
use serde::{Deserialize, Serialize};

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