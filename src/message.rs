use crate::header::{SMBSyncHeader, Header, LegacySMBHeader};
use serde::{Deserialize, Serialize};
use std::str;
use crate::body::{Body, LegacySMBBody, SMBBody};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBMessage<S: Header, T: Body<S>> {
    pub(crate) header: S,
    pub(crate) body: T,
}

impl SMBMessage<SMBSyncHeader, SMBBody> {
    pub fn from_bytes(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let header = SMBSyncHeader::from_bytes(&bytes[4..60])?;
        let (body, carryover) = SMBBody::from_bytes_and_header(&bytes[60..], &header);
        Some((Self { header, body }, carryover))
    }

    pub fn from_legacy(legacy_message: SMBMessage<LegacySMBHeader, LegacySMBBody>) -> Option<Self> {
        let header = SMBSyncHeader::from_legacy_header(legacy_message.header)?;
        let body = SMBBody::LegacyCommand(legacy_message.body);
        return Some(Self { header, body })
    }
}

impl SMBMessage<LegacySMBHeader, LegacySMBBody> {
    pub fn from_bytes(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let header = LegacySMBHeader::from_bytes(&bytes[4..32])?;
        let (body, carryover) = LegacySMBBody::from_bytes_and_header(&bytes[32..], &header);
        Some((Self { header, body }, carryover))
    }
}