use crate::header::{SMBHeader, SMBCommandCode};
use crate::data::SMBData;
use crate::parameters::SMBParameters;
use serde::{Deserialize, Serialize};
use std::str;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBMessage {
    pub(crate) header: SMBHeader,
    pub(crate) parameters: Vec<SMBParameters>,
    pub(crate) data: Vec<SMBData>
}

impl SMBMessage {
    pub fn from_bytes(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let header = SMBHeader::from_bytes(&bytes[0..29])?;
        let (parameters, data, carryover) = Self::parse_body_fields(&bytes[29..], &header);
        Some((Self { header, parameters, data }, carryover))
    }
    fn parse_body_fields<'a>(bytes: &'a [u8], header: &SMBHeader) -> (Vec<SMBParameters>, Vec<SMBData>, &'a [u8]) {
        return match header.command {
            SMBCommandCode::Negotiate => {
                let parameters = Vec::new();
                let count = bytes[0] as usize;
                let sliver = &bytes[1..=count];
                println!("{:?}", sliver);
                for mut protocol in sliver.split(|num| *num == 0x02) {
                    if *protocol.last().unwrap() == 0 {
                        protocol = &protocol[0..(protocol.len() - 1)];
                    }
                    println!("{}", str::from_utf8(protocol).unwrap());
                }
                (parameters, Vec::new(), &bytes[count..])
            },
            _ => (Vec::new(), Vec::new(), bytes)
        }
    }
}