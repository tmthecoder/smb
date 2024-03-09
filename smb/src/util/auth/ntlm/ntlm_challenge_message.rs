use nom::IResult;
use rand::RngCore;
use rand::rngs::ThreadRng;
use serde::{Deserialize, Serialize};

use crate::byte_helper::{u16_to_bytes, u32_to_bytes};
use crate::util::auth::ntlm::ntlm_message::NTLMNegotiateFlags;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Clone)]
pub struct NTLMChallengeMessageBody {
    signature: String,
    target_name: String,
    negotiate_flags: NTLMNegotiateFlags,
    server_challenge: [u8; 8],
}

impl NTLMChallengeMessageBody {
    pub fn new(target_name: String, negotiate_flags: NTLMNegotiateFlags) -> Self {
        let mut server_challenge = [0; 8];
        ThreadRng::default().fill_bytes(&mut server_challenge);
        NTLMChallengeMessageBody {
            signature: "NTLMSSP\0".into(),
            target_name,
            negotiate_flags,
            server_challenge,
        }
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        todo!()
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut name = Vec::new();
        let fakeserver: Vec<u16> = str::encode_utf16("fakeserver").collect();
        for i in fakeserver.iter() {
            let bytes = u16_to_bytes(*i);
            name.push(bytes[0]);
            name.push(bytes[1]);
        }
        [
            self.signature.as_bytes(), // 0 - 8
            &u32_to_bytes(0x02), // 8 - 12
            &u16_to_bytes(20), &u16_to_bytes(20), // 12 - 16
            &u32_to_bytes(56), // 16 - 20
            &u32_to_bytes(self.negotiate_flags.bits()), // 20 - 24
            &self.server_challenge, // 24 - 32
            &[0; 8], // 32 - 40
            &u16_to_bytes(52), &u16_to_bytes(52), // 40-44
            &u32_to_bytes(76), // 44 - 48
            &[6, 1], // NTLM major minor
            &u16_to_bytes(7600), // NTLM build
            &[0, 0, 0, 15], // NTLM current revision
            &name,
            &u16_to_bytes(1),
            &u16_to_bytes(20),
            &*name,
            &u16_to_bytes(2),
            &u16_to_bytes(20),
            &name,
            &[0; 4],
        ].concat()
    }
}

impl NTLMChallengeMessageBody {
    pub fn signature(&self) -> &String {
        &self.signature
    }

    pub fn target_name(&self) -> &String {
        &self.target_name
    }

    pub fn server_challenge(&self) -> &[u8; 8] {
        &self.server_challenge
    }
}