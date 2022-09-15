use serde::{Deserialize, Serialize};
use crate::body::{Body, SMBNegotiationResponse};
use crate::header::{LegacySMBCommandCode, LegacySMBHeader, SMBCommandCode};
use crate::SMBSyncHeader;
use std::str;
use crate::body::negotiate::SMBNegotiationRequestBody;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum SMBBody {
    None,
    NegotiateRequest(SMBNegotiationRequestBody),
    NegotiateResponse(SMBNegotiationResponse),
    LegacyCommand(LegacySMBBody)
}

impl Body<SMBSyncHeader> for SMBBody {
    type Item = SMBBody;

    fn from_bytes_and_header_exists<'a>(bytes: &'a [u8], header: &SMBSyncHeader) -> Option<(Self::Item, &'a [u8])> {
        let body = Self::from_bytes_and_header(bytes, header);
        if body.0 == SMBBody::None {
            return None;
        }
        Some(body)
    }

    fn from_bytes_and_header<'a>(bytes: &'a [u8], header: &SMBSyncHeader) -> (Self::Item, &'a [u8]) {
        match header.command {
            SMBCommandCode::Negotiate => {
                if let Some((negotiation_body, carryover)) = SMBNegotiationRequestBody::from_bytes(bytes) {
                    return (SMBBody::NegotiateRequest(negotiation_body), carryover)
                }
                (SMBBody::None, bytes)
            },
            _ => (SMBBody::None, bytes)
        }
    }

    fn as_bytes(&self) -> Vec<u8> {
        match self {
            SMBBody::NegotiateResponse(x) => {
                x.as_bytes()
            },
            _ => Vec::new()
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

    fn from_bytes_and_header_exists<'a>(bytes: &'a [u8], header: &LegacySMBHeader) -> Option<(Self::Item, &'a [u8])> {
        let body = Self::from_bytes_and_header(bytes, header);
        if body.0 == LegacySMBBody::None {
            return None;
        }
        Some(body)
    }

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

    fn as_bytes(&self) -> Vec<u8> {
        todo!()
    }
}