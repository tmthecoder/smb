use crate::header::{Header, SMBCommandCode, LegacySMBCommandCode, SMBExtra, SMBFlags, SMBStatus, LegacySMBFlags, LegacySMBFlags2};
use serde::{Serialize, Deserialize};
use crate::byte_helper::{bytes_to_u16, bytes_to_u32, bytes_to_u64};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBSyncHeader {
    pub(crate) command: SMBCommandCode,
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

    fn from_bytes(bytes: &[u8]) -> Option<Self::Item> {
        println!("parse 2: {:?}", bytes);
        if bytes.len() < 56 {
            return None;
        }
        let mut signature = [0_u8; 16];
        for (idx, byte) in bytes[40..].iter().enumerate() {
            signature[idx] = *byte;
        }
        println!("status: {}, reserved: {:?}", bytes_to_u32(&bytes[0..4]), &bytes[24..28]);
        Some(SMBSyncHeader {
            command: (bytes_to_u16(& bytes[4..6]) as u8).try_into().ok()?,
            flags: SMBFlags::from_bits_truncate(bytes_to_u32(&bytes[8..12])),
            next_command: bytes_to_u32(&bytes[12..16]),
            message_id: bytes_to_u64(&bytes[16..24]),
            tree_id: bytes_to_u32(&bytes[28..32]),
            session_id: bytes_to_u64(&bytes[32..40]),
            signature,
        })
    }
    fn to_bytes(&self) -> Vec<u8> {
        todo!()
    }
}

impl Header for LegacySMBHeader {
    type Item = LegacySMBHeader;

    fn from_bytes(bytes: &[u8]) -> Option<Self::Item> {
        if bytes.len() < 28 {
            return None;
        }
        Some(LegacySMBHeader {
            command: bytes[0].try_into().ok()?,
            status: SMBStatus::from_bytes(&bytes[1..5])?,
            flags: LegacySMBFlags::from_bits_truncate(bytes[5]),
            flags2: LegacySMBFlags2::from_bits_truncate(bytes_to_u16(&bytes[6..8])),
            extra: SMBExtra::from_bytes(&bytes[8..20]),
            tid: bytes_to_u16(&bytes[20..22]),
            pid: bytes_to_u16(&bytes[22..24]),
            uid: bytes_to_u16(&bytes[24..26]),
            mid: bytes_to_u16(&bytes[26..28]),
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        todo!()
    }
}

impl SMBSyncHeader {
    pub fn from_legacy_header(legacy_header: LegacySMBHeader) -> Option<Self> {
        match legacy_header.command {
            LegacySMBCommandCode::Negotiate => {
                Some(Self {
                    command: SMBCommandCode::Negotiate,
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
}
