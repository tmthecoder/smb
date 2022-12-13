use bitflags::bitflags;
use rand::RngCore;
use rand::rngs::ThreadRng;
use crate::byte_helper::{bytes_to_u32, u16_to_bytes, u32_to_bytes};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub enum NTLMMessage {
    Negotiate(NTLMNegotiateMessageBody),
    Challenge(NTLMChallengeMessageBody),
    Authenticate,
    Dummy
}

impl NTLMMessage {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 24 { return None;}
        match bytes_to_u32(&bytes[8..12]) {
            0x01 => Some(NTLMMessage::Negotiate(NTLMNegotiateMessageBody::from_bytes(bytes)?)),
            0x02 => Some(NTLMMessage::Challenge(NTLMChallengeMessageBody::from_bytes(bytes)?)),
            0x03 => Some(NTLMMessage::Authenticate),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            NTLMMessage::Negotiate(msg) => msg.as_bytes(),
            NTLMMessage::Challenge(msg) => msg.as_bytes(),
            NTLMMessage::Authenticate => todo!(),
            NTLMMessage::Dummy => Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NTLMNegotiateMessageBody {
    signature: String,
    pub negotiate_flags: NTLMNegotiateFlags,
    domain_name: String,
    workstation: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NTLMChallengeMessageBody {
    signature: String,
    target_name: String,
    negotiate_flags: NTLMNegotiateFlags,
    server_challenge: [u8; 8],
}

pub struct NTLMAuthenticateMessageBody {
    signature: String,
    target_name: String,
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

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        None
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
            &u32_to_bytes(self.negotiate_flags.bits), // 20 - 24
            &self.server_challenge, // 24 - 32
            &[0; 8], // 32 - 40
            &u16_to_bytes(52), &u16_to_bytes(52), // 40-44
            &u32_to_bytes(76), // 44 - 48
            &[5, 2], // NTLM major minor
            &u16_to_bytes(3790), // NTLM build
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

bitflags! {
    #[derive(Deserialize, Serialize)]
    pub struct NTLMNegotiateFlags: u32 {
        const UNICODE_ENCODING = 0x01;
        const OEM_ENCODING = 0x02;
        const TARGET_NAME_SUPPLOED = 0x04;
        const SIGN = 0x10;
        const SEAL = 0x20;
        const DATAGRAM = 0x40;
        const LAN_MANAGER_SESSION_KEY = 0x80;
        const NTLM_SESSION_SECURITY = 0x200;
        const ANONYMOUS = 0x800;
        const DOMAIN_NAME_SUPPLIED = 0x1000;
        const WORKSTATION_NAME_SUPPLIED = 0x2000;
        const ALWAYS_SIGN = 0x8000;
        const TARGET_TYPE_DOMAIN = 0x10000;
        const TARGET_TYPE_SERVER = 0x20000;
        const EXTENDED_SESSION_SECURITY = 0x80000;
        const IDENIFY = 0x100000;
        const REQUEST_LM_SESSION_KEY = 0x400000;
        const TARGET_INFO = 0x800000;
        const VERSION = 0x2000000;
        const USE_128_BIT_ENCRYPTION = 0x20000000;
        const KEY_EXCHANGE = 0x40000000;
        const USE_56_BIT_ENCRYPTION = 0x80000000;
    }
}