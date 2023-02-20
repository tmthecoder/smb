use nom::bytes::complete::take;
use nom::combinator::{map, map_res};
use nom::IResult;
use nom::number::complete::le_u32;
use nom::sequence::tuple;
use serde::{Deserialize, Serialize};

use crate::byte_helper::bytes_to_u32;
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

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        map(tuple((
            map_res(take(8_usize), |slice: &[u8]| String::from_utf8(slice.to_vec())),
            take(4_usize),
            map(le_u32, NTLMNegotiateFlags::from_bits_truncate),
            map_res(take(8_usize), |slice: &[u8]| String::from_utf8(slice.to_vec())),
            map_res(take(8_usize), |slice: &[u8]| String::from_utf8(slice.to_vec())),
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