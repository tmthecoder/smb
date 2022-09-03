use crate::header::{SMBHeader, SMBCommandCode};
use serde::{Deserialize, Serialize};
use std::str;
use crate::body::SMBBody;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBMessage {
    pub(crate) header: SMBHeader,
    pub(crate) body: SMBBody,
}

impl SMBMessage {
    pub fn from_bytes(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let header = SMBHeader::from_bytes(&bytes[0..29])?;
        let (body, carryover) = Self::parse_body_fields(&bytes[29..], &header);
        Some((Self { header, body }, carryover))
    }
    fn parse_body_fields<'a>(bytes: &'a [u8], header: &SMBHeader) -> (SMBBody, &'a [u8]) {
        return match header.command {
            SMBCommandCode::Negotiate => {
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
                let body = SMBBody::Negotiate(protocol_strs);
                (body, &bytes[(count + 1)..])
            },
            _ => (SMBBody::None, bytes)
        }
    }
}