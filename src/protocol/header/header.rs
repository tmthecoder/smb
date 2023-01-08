use nom::bytes::complete::{tag, take};
use nom::combinator::{map, map_opt, map_res};
use nom::IResult;
use nom::number::complete::be_u8;
use nom::number::streaming::{be_u16, be_u32, be_u64};
use nom::sequence::tuple;
use serde::{Serialize, Deserialize};
use crate::byte_helper::{bytes_to_u16, bytes_to_u32, bytes_to_u64, u16_to_bytes, u32_to_bytes, u64_to_bytes};
use crate::protocol::header::{Header, LegacySMBCommandCode, LegacySMBFlags, LegacySMBFlags2, SMBCommandCode, SMBExtra, SMBFlags, SMBStatus};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBSyncHeader {
    pub command: SMBCommandCode,
    status: u32,
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
            command: bytes_to_u16(& bytes[8..10]).try_into().ok()?,
            flags: SMBFlags::from_bits_truncate(bytes_to_u32(&bytes[12..16])),
            status: 0,
            next_command: bytes_to_u32(&bytes[16..20]),
            message_id: bytes_to_u64(&bytes[20..28]),
            tree_id: bytes_to_u32(&bytes[32..36]),
            session_id: bytes_to_u64(&bytes[36..44]),
            signature,
        }, &bytes[60..]))
    }

    fn parse(bytes: &[u8]) -> IResult<&[u8], Self::Item> {
        map(tuple((
            take::<_, &[u8], _>(8_usize),
            map_res(be_u16, SMBCommandCode::try_from),
            take(2_usize),
            map(be_u32, SMBFlags::from_bits_truncate),
            be_u32,
            be_u64,
            be_u32,
            be_u64,
            map_res(take(16_usize), |arr: &[u8]| <([u8; 16])>::try_from(arr)),
        )), |(a, command, _, flags, next_command, message_id, tree_id, session_id, signature)| Self {
            command,
            status: 0,
            flags,
            next_command,
            message_id,
            tree_id,
            session_id,
            signature
        })(bytes)
    }

    fn as_bytes(&self) -> Vec<u8> {
        [
            &[0xFE_u8],
            &b"SMB"[0..],
            &[64, 0], // Structure size,
            &[0; 2], // Credit
            &u32_to_bytes(self.status), // Reserved/Status/TODO
            &u16_to_bytes(self.command as u16),
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

    fn parse(bytes: &[u8]) -> IResult<&[u8], Self::Item> {
        map(tuple((
            map_res(be_u8, LegacySMBCommandCode::try_from),
            map_opt(take(4_usize), SMBStatus::from_bytes),
            map(be_u8, LegacySMBFlags::from_bits_truncate),
            map(be_u16, LegacySMBFlags2::from_bits_truncate),
            map(take(12_usize), SMBExtra::from_bytes),
            be_u16,
            be_u16,
            be_u16,
            be_u16,
        )), |(command, status, flags, flags2, extra, tid, pid, uid, mid)| Self {
            command,
            status,
            flags,
            flags2,
            extra,
            tid,
            pid,
            uid,
            mid
        })(bytes)
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
            status: 0,
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
                    status: 0,
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

    pub fn create_response_header(&self, status: u32) -> Self {
        Self {
            command: self.command,
            flags: SMBFlags::SERVER_TO_REDIR,
            status,
            next_command: 0,
            message_id: self.message_id,
            tree_id: self.tree_id,
            session_id: self.session_id,
            signature: [1; 16]
        }
    }
}
