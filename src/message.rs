use crate::header::{SMBHeader, Header, LegacySMBHeader};
use serde::{Deserialize, Serialize};
use std::str;
use crate::body::{Body, LegacySMBBody, SMBBody};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBMessage<S: Header, T: Body<S>> {
    pub(crate) header: S,
    pub(crate) body: T,
}

impl SMBMessage<SMBHeader, SMBBody> {
    pub fn from_bytes(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let header = SMBHeader::from_bytes(&bytes[4..60])?;
        println!("GOT HEADER");
        let (body, carryover) = SMBBody::from_bytes_and_header(&bytes[60..], &header);
        Some((Self { header, body }, carryover))
    }
}