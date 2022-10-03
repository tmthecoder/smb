use crate::header::{Header, SMBCommandCode, LegacySMBCommandCode, SMBExtra, SMBFlags, SMBStatus, LegacySMBFlags, LegacySMBFlags2};
use serde::{Serialize, Deserialize};
use crate::byte_helper::{bytes_to_u16, bytes_to_u32, bytes_to_u64, u16_to_bytes, u32_to_bytes, u64_to_bytes};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBSyncHeader {
    pub command: SMBCommandCode,
    flags: SMBFlags,
    next_command: u32,
    message_id: u64,
    tree_id: u32,
    session_id: u64,
    signature: [u8; 16],
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct LegacySMBHeader {
    pub(crate) command: LegacySMBCommandCode,
    status: SMBStatus,
    flags: LegacySMBFlags,
    flags2: LegacySMBFlags2,
    extra: SMBExtra,
    tid: u16,
    pid: u16,
    uid: u16,
    mid: u16
}

impl Header for SMBSyncHeader {
    type Item = SMBSyncHeader;

    fn from_bytes(bytes: &[u8]) -> Option<(Self::Item, &[u8])> {
        println!("parse 2: {:?}", bytes);
        if bytes.len() < 60 {
            return None;
        }
        let mut signature = [0_u8; 16];
        for (idx, byte) in bytes[44..60].iter().enumerate() {
            signature[idx] = *byte;
        }
        println!("status: {}, reserved: {:?}", bytes_to_u32(&bytes[4..8]), &bytes[28..32]);
        Some((SMBSyncHeader {
            command: (bytes_to_u16(& bytes[8..10]) as u8).try_into().ok()?,
            flags: SMBFlags::from_bits_truncate(bytes_to_u32(&bytes[12..16])),
            next_command: bytes_to_u32(&bytes[16..20]),
            message_id: bytes_to_u64(&bytes[20..28]),
            tree_id: bytes_to_u32(&bytes[32..36]),
            session_id: bytes_to_u64(&bytes[36..44]),
            signature,
        }, &bytes[60..]))
    }
    fn as_bytes(&self) -> Vec<u8> {
        [
            &[0xFE_u8],
            &b"SMB"[0..],
            &[64, 0], // Structure size,
            &[0; 2], // Credit
            &[0; 4], // Reserved/Status/TODO
            &[0, self.command as u8],
            &[0; 2], // CreditResponse,
            &u32_to_bytes(self.flags.bits()),
            &[0; 4], // Next Command,
            &u64_to_bytes(self.message_id),
            &[0, 0, 0xFE, 0xFF], // Reserved
            &u32_to_bytes(self.tree_id),
            &u64_to_bytes(self.session_id),
            &self.signature
        ].concat()
    }
}

impl Header for LegacySMBHeader {
    type Item = LegacySMBHeader;

    fn from_bytes(bytes: &[u8]) -> Option<(Self::Item, &[u8])> {
        if bytes.len() < 28 {
            return None;
        }
        Some((LegacySMBHeader {
            command: bytes[0].try_into().ok()?,
            status: SMBStatus::from_bytes(&bytes[1..5])?,
            flags: LegacySMBFlags::from_bits_truncate(bytes[5]),
            flags2: LegacySMBFlags2::from_bits_truncate(bytes_to_u16(&bytes[6..8])),
            extra: SMBExtra::from_bytes(&bytes[8..20]),
            tid: bytes_to_u16(&bytes[20..22]),
            pid: bytes_to_u16(&bytes[22..24]),
            uid: bytes_to_u16(&bytes[24..26]),
            mid: bytes_to_u16(&bytes[26..28]),
        }, &bytes[28..]))
    }

    fn as_bytes(&self) -> Vec<u8> {
        [
            &[0xFF_u8],
            &b"SMB"[0..],
            &[self.command as u8],
            &*self.status.as_bytes(),
            &[self.flags.bits()],
            &u16_to_bytes(self.flags2.bits()),
            &*self.extra.as_bytes(),
            &u16_to_bytes(self.tid),
            &u16_to_bytes(self.pid),
            &u16_to_bytes(self.uid),
            &u16_to_bytes(self.mid)
        ].concat()
    }
}

impl SMBSyncHeader {
    pub fn new(command: SMBCommandCode, flags: SMBFlags, next_command: u32, message_id: u64, tree_id: u32, session_id: u64, signature: [u8; 16]) -> Self {
        SMBSyncHeader {
            command,
            flags,
            next_command,
            message_id,
            tree_id,
            session_id,
            signature
        }
    }

    pub fn from_legacy_header(legacy_header: LegacySMBHeader) -> Option<Self> {
        match legacy_header.command {
            LegacySMBCommandCode::Negotiate => {
                Some(Self {
                    command: SMBCommandCode::LegacyNegotiate,
                    flags: SMBFlags::empty(),
                    next_command: 0,
                    message_id: legacy_header.mid as u64,
                    tree_id: legacy_header.tid as u32,
                    session_id: legacy_header.uid as u64,
                    signature: [0; 16]
                })
            },
            _ => None
        }
    }

    pub fn create_response_header(&self) -> Self {
        Self {
            command: self.command,
            flags: SMBFlags::SERVER_TO_REDIR,
            next_command: 0,
            message_id: self.message_id,
            tree_id: self.tree_id,
            session_id: self.session_id,
            signature: [1; 16]
        }
    }
}
