use des::cipher::KeyInit;
use nom::bytes::complete::take;
use nom::combinator::{map, map_res};
use nom::IResult;
use nom::number::complete::le_u32;
use nom::sequence::tuple;
use rc4::{Key, Rc4, StreamCipher};
use rc4::consts::U16;
use serde::{Deserialize, Serialize};

use crate::util::auth::ntlm::ntlm_auth_provider::NTLMAuthContext;
use crate::util::auth::ntlm::ntlm_message::{NTLMNegotiateFlags, parse_ntlm_buffer_fields};
use crate::util::auth::user::User;
use crate::util::crypto::ntlm_v1_extended::authenticate_v1_extended;
use crate::util::crypto::ntlm_v2::authenticate_v2;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Clone)]
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
            take(8_usize),
            take(16_usize),
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
                    _,
                    mic
                ),
            )| {
                let (_, lm_challenge_response) =
                    get_buffer(lm_challenge_info.0, lm_challenge_info.1, bytes)?;
                let (_, nt_challenge_response) =
                    get_buffer(nt_challenge_info.0, nt_challenge_info.1, bytes)?;
                let (_, domain_name) = map(map_res(
                    |bytes| get_buffer(domain_name_into.0, domain_name_into.1, bytes),
                    String::from_utf8,
                ), |s| s.replace('\0', ""))(bytes)?;
                let (_, user_name) = map(map_res(
                    |bytes| get_buffer(user_name_info.0, user_name_info.1, bytes),
                    String::from_utf8,
                ), |s| s.replace('\0', ""))(bytes)?;
                let (_, work_station) = map(map_res(
                    |bytes| get_buffer(work_station_info.0, work_station_info.1, bytes),
                    String::from_utf8,
                ), |s| s.replace('\0', ""))(bytes)?;
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
                        mic: mic.into(),
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
        context.user_name = Some(self.user_name.clone().replace('\0', ""));
        context.work_station = Some(self.work_station.clone());

        context.version = Some("6.1.7200".into()); // TODO FIX
        smb_core::logging::trace!(?self.negotiate_flags, "NTLM authenticate message");
        if self.negotiate_flags.contains(NTLMNegotiateFlags::ANONYMOUS) {
            return if guest_supported {
                context.guest = Some(true);
                0
            } else {
                1 // TODO failure
            }
        }

        // TODO check if remaining attempts are allowed
        let matched_user = accepted_users
            .iter()
            .find(|user| user.username == self.user_name);
        if matched_user.is_none() {
            return if guest_supported {
                context.guest = Some(true);
                0
            } else {
                1 // TODO login counter and failure
            };
        }

        let matched_user = matched_user.unwrap();

        let server_challenge = &context.server_challenge;
        let response_key: Vec<u8> = if self
            .negotiate_flags
            .contains(NTLMNegotiateFlags::EXTENDED_SESSION_SECURITY)
        {
            if self.lm_challenge_response.len() == 24 && self.lm_challenge_response[0..8] != [0; 8] {
                // ntlm v1 extended
                let response = authenticate_v1_extended(&matched_user.password, server_challenge, &self.lm_challenge_response, &self.nt_challenge_response);
                Vec::new()
            } else {
                // ntlm v2
                let (_, session_base_key) = authenticate_v2(&self.domain_name, &self.user_name, &matched_user.password, server_challenge, &self.lm_challenge_response, &self.nt_challenge_response).unwrap();
                session_base_key
            }
        } else {
            Vec::new()
        };
        if !response_key.is_empty() && self.negotiate_flags.contains(NTLMNegotiateFlags::KEY_EXCHANGE) {
            let session_key = if self.negotiate_flags.contains(NTLMNegotiateFlags::SEAL) || self.negotiate_flags.contains(NTLMNegotiateFlags::SIGN) {
                let mut rc4 = Rc4::new(Key::<U16>::from_slice(&response_key));
                let mut output = vec![0; self.encrypted_session_key.len()];
                rc4.apply_keystream_b2b(&self.encrypted_session_key, &mut output).unwrap();
                output 
            } else {
                response_key
            };
            context.session_key = session_key;
            0
        } else { 1 }

    }
}


fn get_buffer(length: u16, offset: u32, buffer: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (remaining, slice) = take(offset as usize)(buffer)
        .and_then(|(remaining, _)| take(length as usize)(remaining))?;
    Ok((remaining, slice.to_vec()))
}

