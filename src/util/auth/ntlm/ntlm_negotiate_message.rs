use nom::bytes::complete::take;
use nom::combinator::{map, map_res};
use nom::IResult;
use nom::number::complete::le_u32;
use nom::sequence::tuple;
use serde::{Deserialize, Serialize};

use crate::util::auth::nt_status::NTStatus;
use crate::util::auth::ntlm::ntlm_message::NTLMNegotiateFlags;
use crate::util::auth::ntlm::NTLMChallengeMessageBody;

#[derive(Debug, Deserialize, Serialize)]
pub struct NTLMNegotiateMessageBody {
    signature: String,
    pub negotiate_flags: NTLMNegotiateFlags,
    domain_name: String,
    workstation: String,
}

impl NTLMNegotiateMessageBody {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        map(
            tuple((
                map_res(take(8_usize), |slice: &[u8]| {
                    String::from_utf8(slice.to_vec())
                }),
                take(4_usize),
                map(le_u32, NTLMNegotiateFlags::from_bits_truncate),
                map_res(take(8_usize), |slice: &[u8]| {
                    String::from_utf8(slice.to_vec())
                }),
                map_res(take(8_usize), |slice: &[u8]| {
                    String::from_utf8(slice.to_vec())
                }),
            )),
            |(signature, _, negotiate_flags, domain_name, workstation)| Self {
                signature,
                negotiate_flags,
                domain_name,
                workstation,
            },
        )(bytes)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        [self.signature.as_bytes()].concat()
    }
}

impl NTLMNegotiateMessageBody {
    pub fn get_challenge_response(&self) -> (NTStatus, NTLMChallengeMessageBody) {
        fn add_if_present(
            flags: &mut NTLMNegotiateFlags,
            original: &NTLMNegotiateFlags,
            to_add: NTLMNegotiateFlags,
        ) {
            if original.contains(to_add) {
                flags.insert(to_add);
            }
        }

        fn add_if_else_present(
            flags: &mut NTLMNegotiateFlags,
            original: &NTLMNegotiateFlags,
            to_add: NTLMNegotiateFlags,
            fallback: NTLMNegotiateFlags,
        ) {
            if original.contains(to_add) {
                flags.insert(to_add);
            } else if original.contains(fallback) {
                flags.insert(fallback);
            }
        }
        let mut negotiate_flags = NTLMNegotiateFlags::TARGET_TYPE_SERVER
            | NTLMNegotiateFlags::TARGET_INFO
            | NTLMNegotiateFlags::TARGET_NAME_SUPPLOED
            | NTLMNegotiateFlags::VERSION
            | NTLMNegotiateFlags::NTLM_SESSION_SECURITY;

        add_if_else_present(
            &mut negotiate_flags,
            &self.negotiate_flags,
            NTLMNegotiateFlags::UNICODE_ENCODING,
            NTLMNegotiateFlags::OEM_ENCODING,
        );
        add_if_else_present(
            &mut negotiate_flags,
            &self.negotiate_flags,
            NTLMNegotiateFlags::EXTENDED_SESSION_SECURITY,
            NTLMNegotiateFlags::LAN_MANAGER_SESSION_KEY,
        );

        add_if_present(
            &mut negotiate_flags,
            &self.negotiate_flags,
            NTLMNegotiateFlags::SIGN,
        );
        add_if_present(
            &mut negotiate_flags,
            &self.negotiate_flags,
            NTLMNegotiateFlags::SEAL,
        );
        if self.negotiate_flags.contains(NTLMNegotiateFlags::SIGN)
            || self.negotiate_flags.contains(NTLMNegotiateFlags::SEAL)
        {
            add_if_present(
                &mut negotiate_flags,
                &self.negotiate_flags,
                NTLMNegotiateFlags::USE_56_BIT_ENCRYPTION,
            );
            add_if_present(
                &mut negotiate_flags,
                &self.negotiate_flags,
                NTLMNegotiateFlags::USE_128_BIT_ENCRYPTION,
            );
        }
        add_if_present(
            &mut negotiate_flags,
            &self.negotiate_flags,
            NTLMNegotiateFlags::KEY_EXCHANGE,
        );

        let target_name = "fakeserver";

        (NTStatus::SecIContinueNeeded, NTLMChallengeMessageBody::new(target_name.into(), negotiate_flags))
    }
}

