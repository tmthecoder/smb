use nom::bytes::complete::take;
use nom::combinator::{map, map_res};
use nom::IResult;
use nom::number::complete::le_u32;
use nom::sequence::tuple;
use serde::{Deserialize, Serialize};

use crate::byte_helper::bytes_to_u32;
use crate::util::auth::ntlm::ntlm_auth_provider::NTLMAuthContext;
use crate::util::auth::ntlm::ntlm_message::{NTLMNegotiateFlags, parse_ntlm_buffer_ptr, read_ntlm_buffer_ptr};
use crate::util::auth::User;

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

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        map(tuple((
            map_res(take(8_usize), |s: &[u8]| String::from_utf8(s.to_vec())),
            take(4_usize),
            map(parse_ntlm_buffer_ptr, |s| s.to_vec()),
            map(parse_ntlm_buffer_ptr, |s| s.to_vec()),
            map_res(parse_ntlm_buffer_ptr, |s: &[u8]| String::from_utf8(s.to_vec())),
            map_res(parse_ntlm_buffer_ptr, |s: &[u8]| String::from_utf8(s.to_vec())),
            map_res(parse_ntlm_buffer_ptr, |s: &[u8]| String::from_utf8(s.to_vec())),
            map(parse_ntlm_buffer_ptr, |s| s.to_vec()),
            map(le_u32, NTLMNegotiateFlags::from_bits_truncate)
        )), |(signature, _, lm_challenge_response, nt_challenge_response, domain_name, user_name, work_station, encrypted_session_key, negotiate_flags)| Self {
            signature,
            lm_challenge_response,
            nt_challenge_response,
            domain_name,
            user_name,
            work_station,
            encrypted_session_key,
            negotiate_flags,
            mic: Vec::new(),
        })(bytes)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        Vec::new()
    }
}

impl NTLMAuthenticateMessageBody {
    pub fn authenticate(&self, context: &mut NTLMAuthContext, accepted_users: &[User], guest_supported: bool) -> u8 {
        context.domain_name = Some(self.domain_name.clone());
        context.user_name = Some(self.user_name.clone());
        context.work_station = Some(self.work_station.clone());

        context.version = Some("6.1.7200".into()); // TODO FIX
        if self.negotiate_flags.contains(NTLMNegotiateFlags::ANONYMOUS) {
            if guest_supported {
                context.guest = Some(true);
                return 0;
            } else {
                return 1; // TODO failure
            }
        }

        // TODO check if remaining attempts are allowed

        let password = accepted_users.iter().find(|user| user.username == self.user_name);
        if password.is_none() {
            if guest_supported {
                context.guest = Some(true);
                return 0;
            } else {
                return 1; // TODO login counter and failure
            }
        }

        if self.negotiate_flags.contains(NTLMNegotiateFlags::EXTENDED_SESSION_SECURITY) {

        }

        0
    }
}