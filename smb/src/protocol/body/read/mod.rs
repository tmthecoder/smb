use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::read::channel::SMBRWChannel;
use crate::protocol::body::read::flags::{SMBReadRequestFlags, SMBReadResponseFlags};

mod flags;
pub mod channel;

#[derive(
    Debug,
    PartialEq,
    Eq,
    SMBByteSize,
    SMBToBytes,
    SMBFromBytes,
    Serialize,
    Deserialize,
    Clone
)]
#[smb_byte_tag(value = 49)]
pub struct SMBReadRequest {
    #[smb_direct(start(fixed = 3))]
    flags: SMBReadRequestFlags,
    #[smb_direct(start(fixed = 4))]
    read_length: u32,
    #[smb_direct(start(fixed = 8))]
    read_offset: u64,
    #[smb_direct(start(fixed = 16))]
    file_id: SMBFileId,
    #[smb_direct(start(fixed = 32))]
    minimum_count: u32,
    #[smb_direct(start(fixed = 36))]
    channel: SMBRWChannel,
    #[smb_direct(start(fixed = 40))]
    remaining_bytes: u32,
    #[smb_buffer(offset(inner(start = 44, num_type = "u16", subtract = 64)), length(inner(start = 46, num_type = "u16")))]
    channel_information: Vec<u8>,
}

impl SMBReadRequest {
    pub fn file_id(&self) -> &SMBFileId {
        &self.file_id
    }

    pub fn read_length(&self) -> u32 {
        self.read_length
    }

    pub fn read_offset(&self) -> u64 {
        self.read_offset
    }

    pub fn minimum_count(&self) -> u32 {
        self.minimum_count
    }
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    SMBByteSize,
    SMBToBytes,
    SMBFromBytes,
    Serialize,
    Deserialize,
    Clone
)]
#[smb_byte_tag(value = 17)]
pub struct SMBReadResponse {
    #[smb_skip(start = 3, length = 1)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 8))]
    data_remaining: u32,
    #[smb_direct(start(fixed = 12))]
    flags: SMBReadResponseFlags,
    #[smb_buffer(order = 0, offset(inner(start = 2, num_type = "u8", subtract = 64)), length(inner(start = 4, num_type = "u32")))]
    data: Vec<u8>,
}

impl SMBReadResponse {
    pub fn new(data: Vec<u8>, data_remaining: u32) -> Self {
        Self {
            reserved: PhantomData,
            data_remaining,
            flags: SMBReadResponseFlags::None,
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBByteSize, SMBToBytes, SMBFromBytes};

    #[test]
    fn read_response_new_sets_fields() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let resp = SMBReadResponse::new(data.clone(), 100);
        assert_eq!(resp.data, data);
        assert_eq!(resp.data_remaining, 100);
        assert_eq!(resp.flags, SMBReadResponseFlags::None);
    }

    #[test]
    fn read_response_serialization_round_trip() {
        let resp = SMBReadResponse::new(vec![1, 2, 3, 4, 5], 0);
        let bytes = resp.smb_to_bytes();
        assert_eq!(bytes.len(), resp.smb_byte_size());
        let (_, parsed) = SMBReadResponse::smb_from_bytes(&bytes).unwrap();
        assert_eq!(resp, parsed);
    }

    #[test]
    fn read_response_empty_data() {
        let resp = SMBReadResponse::new(vec![], 0);
        let bytes = resp.smb_to_bytes();
        let (_, parsed) = SMBReadResponse::smb_from_bytes(&bytes).unwrap();
        assert_eq!(resp, parsed);
    }

    #[test]
    fn read_request_accessors() {
        let bytes = {
            let mut buf = Vec::new();
            // struct_size (u16) = 49
            buf.extend_from_slice(&49u16.to_le_bytes());
            // padding (u8)
            buf.push(0);
            // flags (u8) = 0
            buf.push(0);
            // read_length (u32) = 1024
            buf.extend_from_slice(&1024u32.to_le_bytes());
            // read_offset (u64) = 512
            buf.extend_from_slice(&512u64.to_le_bytes());
            // file_id: persistent (u64) + volatile (u64)
            buf.extend_from_slice(&10u64.to_le_bytes());
            buf.extend_from_slice(&20u64.to_le_bytes());
            // minimum_count (u32) = 256
            buf.extend_from_slice(&256u32.to_le_bytes());
            // channel (u32) = 0
            buf.extend_from_slice(&0u32.to_le_bytes());
            // remaining_bytes (u32) = 0
            buf.extend_from_slice(&0u32.to_le_bytes());
            // channel_info_offset (u16) = 0, channel_info_length (u16) = 0
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf
        };
        let (_, req) = SMBReadRequest::smb_from_bytes(&bytes).unwrap();
        assert_eq!(req.read_length(), 1024);
        assert_eq!(req.read_offset(), 512);
        assert_eq!(req.minimum_count(), 256);
        assert_eq!(req.file_id().persistent, 10);
        assert_eq!(req.file_id().volatile, 20);
    }
}