use std::str::from_utf8;
use serde::{Deserialize, Serialize};
use crate::byte_helper::bytes_to_u32;
use crate::util::auth::ntlm::ntlm_message::{NTLMNegotiateFlags, read_ntlm_buffer_ptr};

#[derive(Debug, Deserialize, Serialize)]
pub struct NTLMAuthenticateMessageBody {
    signature: String,
    negotiate_flags: NTLMNegotiateFlags,
    domain_name: String,
    user_name: String,
    work_station: String,
    lm_challenge_response: Vec<u8>,
    nt_challenge_response: Vec<u8>,
    encrypted_session_key: Vec<u8>,
    mic: Vec<u8>,
}

impl NTLMAuthenticateMessageBody {
    pub fn from_bytes(bytes: &[u8]) -> Option<NTLMAuthenticateMessageBody> {
        let signature = String::from_utf8(bytes[..8].to_vec()).ok()?;
        let lm_challenge_response = read_ntlm_buffer_ptr(bytes, 12)?;
        let nt_challenge_response = read_ntlm_buffer_ptr(bytes, 20)?;
        let domain_name = String::from_utf8(read_ntlm_buffer_ptr(bytes, 28)?).ok()?;
        let user_name = String::from_utf8(read_ntlm_buffer_ptr(bytes, 36)?).ok()?;
        let work_station = String::from_utf8(read_ntlm_buffer_ptr(bytes, 44)?).ok()?;
        let encrypted_session_key = read_ntlm_buffer_ptr(bytes, 52)?;
        let negotiate_flags = NTLMNegotiateFlags::from_bits(bytes_to_u32(&bytes[60..64]))?;

        Some(Self {
            signature,
            negotiate_flags,
            domain_name,
            user_name,
            work_station,
            lm_challenge_response,
            nt_challenge_response,
            encrypted_session_key,
            mic: Vec::new(),
        })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        Vec::new()
    }
}

impl NTLMAuthenticateMessageBody {
    pub fn authenticate(&self) -> u8 {

    }
}