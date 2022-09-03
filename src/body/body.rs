use serde::{Deserialize, Serialize};
use crate::body::Body;
use crate::header::{LegacySMBCommandCode, LegacySMBHeader, SMBCommandCode};
use crate::SMBSyncHeader;
use std::str;
use crate::body::negotiate::{SMBDialect, SMBNegotiationBody};
use crate::byte_helper::bytes_to_u16;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum SMBBody {
    None,
    Negotiate(SMBNegotiationBody),

}

impl Body<SMBSyncHeader> for SMBBody {
    type Item = SMBBody;

    fn from_bytes_and_header<'a>(bytes: &'a [u8], header: &SMBSyncHeader) -> (Self::Item, &'a [u8]) {
        match header.command {
            SMBCommandCode::Negotiate => {
                let (negotiation_body, carryover) = SMBNegotiationBody::from_bytes(bytes);
                (SMBBody::Negotiate(negotiation_body), carryover)
            },
            _ => (SMBBody::None, bytes)
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum LegacySMBBody {
    None,
    Negotiate(Vec<String>)
}

impl Body<LegacySMBHeader> for LegacySMBBody {
    type Item = LegacySMBBody;

    fn from_bytes_and_header<'a>(bytes: &'a [u8], header: &LegacySMBHeader) -> (Self::Item, &'a [u8]) {
        return match header.command {
            LegacySMBCommandCode::Negotiate => {
                let count = bytes[0] as usize;
                let sliver = &bytes[1..=count];
                println!("{:?}", sliver);
                let protocol_strs: Vec<String> = sliver.split(|num| *num == 0x02).filter_map(|mut protocol| {
                    if let Some(x) = protocol.last() {
                        if *x == 0 {
                            protocol = &protocol[0..(protocol.len() - 1)];
                        }
                        if protocol.is_empty() { return None; }
                        Some(str::from_utf8(protocol).ok()?.to_owned())
                    } else {
                        None
                    }
                }).collect();
                let body = LegacySMBBody::Negotiate(protocol_strs);
                (body, &bytes[(count + 1)..])
            },
            _ => (LegacySMBBody::None, bytes)
        }
    }
}