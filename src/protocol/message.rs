use serde::{Deserialize, Serialize};
use std::str;
use nom::IResult;
use nom::sequence::preceded;
use crate::byte_helper::u16_to_bytes;
use crate::protocol::body::{Body, LegacySMBBody, SMBBody};
use crate::protocol::header::{Header, LegacySMBHeader, SMBSyncHeader};

pub type SMBSyncMessage = SMBMessage<SMBSyncHeader, SMBBody>;
pub type SMBLegacyMessage = SMBMessage<LegacySMBHeader, LegacySMBBody>;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBMessage<S: Header, T: Body<S>> {
    pub header: S,
    pub body: T,
}

impl<S: Header, T: Body<S>> SMBMessage<S, T> {
    pub fn new(header: S, body: T) -> Self {
        SMBMessage {
            header,
            body
        }
    }
}

pub trait Message {
    fn from_bytes_assert_body(bytes: &[u8]) -> Option<(Self, &[u8])> where Self: Sized;
    fn from_bytes(bytes: &[u8]) -> Option<(Self, &[u8])> where Self: Sized;
    fn as_bytes(&self) -> Vec<u8>;
    fn parse(bytes: &[u8]) -> IResult<&[u8], Self> where Self: Sized;
}

impl SMBMessage<SMBSyncHeader, SMBBody> {
    pub fn from_legacy(legacy_message: SMBMessage<LegacySMBHeader, LegacySMBBody>) -> Option<Self> {
        let header = SMBSyncHeader::from_legacy_header(legacy_message.header)?;
        let body = SMBBody::LegacyCommand(legacy_message.body);
        Some(Self { header, body })
    }
}

impl<S: Header, T:  Body<S>> Message for SMBMessage<S, T> {
    fn from_bytes_assert_body(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let (remaining_bytes, header) = S::parse(bytes).ok()?;
        let (body, carryover) = T::from_bytes_and_header_exists(remaining_bytes, &header)?;
        Some((Self { header, body }, carryover))
    }

    fn from_bytes(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let (remaining_bytes, header) = S::parse(bytes).ok()?;
        let (body, carryover) = T::from_bytes_and_header(remaining_bytes, &header);
        Some((Self { header, body }, carryover))
    }

    fn as_bytes(&self) -> Vec<u8> {
        let smb2_message = [self.header.as_bytes(), self.body.as_bytes()].concat();
        let mut len_bytes = u16_to_bytes(smb2_message.len() as u16);
        len_bytes.reverse();
        [[0, 0].to_vec(), len_bytes.to_vec(), self.header.as_bytes(), self.body.as_bytes()].concat()
    }

    fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        todo!()
    }
}