use std::fmt::Debug;
use std::str;

use serde::{Deserialize, Serialize};

use smb_core::SMBParseResult;

use crate::byte_helper::u16_to_bytes;
use crate::protocol::body::{Body, LegacySMBBody, SMBBody};
use crate::protocol::header::{Header, LegacySMBHeader, SMBSyncHeader};

pub type SMBSyncMessage = SMBMessage<SMBSyncHeader, SMBBody>;
pub type SMBLegacyMessage = SMBMessage<LegacySMBHeader, LegacySMBBody>;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
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
    fn as_bytes(&self) -> Vec<u8>;
    fn parse(bytes: &[u8]) -> SMBParseResult<&[u8], Self> where Self: Sized;
}

impl SMBMessage<SMBSyncHeader, SMBBody> {
    pub fn from_legacy(legacy_message: SMBMessage<LegacySMBHeader, LegacySMBBody>) -> Option<Self> {
        let header = SMBSyncHeader::from_legacy_header(legacy_message.header)?;
        let body = SMBBody::LegacyCommand(legacy_message.body);
        Some(Self { header, body })
    }
}

impl<S: Header, T: Body<S>> Message for SMBMessage<S, T> {
    fn as_bytes(&self) -> Vec<u8> {
        let smb2_message = [self.header.smb_to_bytes(), self.body.as_bytes()].concat();
        println!("Header act: {:?}", self.header.as_bytes());
        println!("Header tst: {:?}", self.header.smb_to_bytes());
        let mut len_bytes = u16_to_bytes(smb2_message.len() as u16);
        len_bytes.reverse();
        [[0, 0].to_vec(), len_bytes.to_vec(), smb2_message].concat()
    }

    fn parse(bytes: &[u8]) -> SMBParseResult<&[u8], Self> {
        let (remaining, header) = S::smb_from_bytes(bytes)?;
        let (remaining, body) = T::parse_with_cc(remaining, header.command_code())?;
        Ok((remaining, Self { header, body }))
    }
}