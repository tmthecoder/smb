use nom::bytes::complete::take;
use nom::combinator::{map, map_res};
use nom::number::complete::le_u32;
use nom::sequence::tuple;
use nom::IResult;
use serde::{Deserialize, Serialize};

use crate::util::auth::ntlm::ntlm_auth_provider::NTLMAuthContext;
use crate::util::auth::ntlm::ntlm_message::{parse_ntlm_buffer_fields, NTLMNegotiateFlags};
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
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        tuple((
            map_res(take(8_usize), |s: &[u8]| String::from_utf8(s.to_vec())),
            take(4_usize),
            parse_ntlm_buffer_fields,
            parse_ntlm_buffer_fields,
            parse_ntlm_buffer_fields,
            parse_ntlm_buffer_fields,
            parse_ntlm_buffer_fields,
            parse_ntlm_buffer_fields,
            map(le_u32, NTLMNegotiateFlags::from_bits_truncate),
        ))(bytes)
        .and_then(
            |(
                _,
                (
                    signature,
                    _,
                    lm_challenge_info,
                    nt_challenge_info,
                    domain_name_into,
                    user_name_info,
                    work_station_info,
                    encrypted_session_key_info,
                    negotiate_flags,
                ),
            )| {
                let (_, lm_challenge_response) =
                    get_buffer(lm_challenge_info.0, lm_challenge_info.1, bytes)?;
                let (_, nt_challenge_response) =
                    get_buffer(nt_challenge_info.0, nt_challenge_info.1, bytes)?;
                let (_, domain_name) = map_res(
                    |bytes| get_buffer(domain_name_into.0, domain_name_into.1, bytes),
                    String::from_utf8,
                )(bytes)?;
                let (_, user_name) = map_res(
                    |bytes| get_buffer(user_name_info.0, user_name_info.1, bytes),
                    String::from_utf8,
                )(bytes)?;
                let (_, work_station) = map_res(
                    |bytes| get_buffer(work_station_info.0, work_station_info.1, bytes),
                    String::from_utf8,
                )(bytes)?;
                let (remaining, encrypted_session_key) = get_buffer(
                    encrypted_session_key_info.0,
                    encrypted_session_key_info.1,
                    bytes,
                )?;
                Ok((
                    remaining,
                    Self {
                        signature,
                        negotiate_flags,
                        domain_name,
                        user_name,
                        work_station,
                        lm_challenge_response,
                        nt_challenge_response,
                        encrypted_session_key,
                        mic: Vec::new(),
                    },
                ))
            },
        )
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        Vec::new()
    }
}

impl NTLMAuthenticateMessageBody {
    pub fn authenticate(
        &self,
        context: &mut NTLMAuthContext,
        accepted_users: &[User],
        guest_supported: bool,
    ) -> u8 {
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

        let password = accepted_users
            .iter()
            .find(|user| user.username == self.user_name);
        if password.is_none() {
            return if guest_supported {
                context.guest = Some(true);
                0
            } else {
                1 // TODO login counter and failure
            };
        }

        if self
            .negotiate_flags
            .contains(NTLMNegotiateFlags::EXTENDED_SESSION_SECURITY)
        {}

        0
    }
}

fn get_buffer(length: u16, offset: u32, buffer: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (remaining, slice) = take(offset as usize)(buffer)
        .and_then(|(remaining, _)| take(length as usize)(remaining))?;
    Ok((remaining, slice.to_vec()))
}

