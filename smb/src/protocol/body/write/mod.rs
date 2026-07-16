use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::read::channel::SMBRWChannel;
use crate::protocol::body::write::flags::SMBWriteFlags;

mod flags;

#[derive(
    Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize, Clone,
)]
#[smb_byte_tag(value = 49)]
pub struct SMBWriteRequest {
    #[smb_direct(start(fixed = 4))]
    write_length: u32,
    #[smb_direct(start(fixed = 8))]
    write_offset: u64,
    #[smb_direct(start(fixed = 16))]
    file_id: SMBFileId,
    #[smb_direct(start(fixed = 32))]
    channel: SMBRWChannel,
    #[smb_direct(start(fixed = 36))]
    remaining_bytes: u32,
    #[smb_direct(start(fixed = 44))]
    flags: SMBWriteFlags,
    #[smb_buffer(
        offset(inner(start = 40, num_type = "u16", subtract = 64)),
        length(inner(start = 42, num_type = "u16"))
    )]
    channel_information: Vec<u8>,
    #[smb_buffer(
        offset(inner(start = 2, num_type = "u16", subtract = 64)),
        length(inner(start = 4, num_type = "u32"))
    )]
    data_to_write: Vec<u8>,
}

impl SMBWriteRequest {
    pub fn file_id(&self) -> &SMBFileId {
        &self.file_id
    }

    pub fn write_offset(&self) -> u64 {
        self.write_offset
    }

    pub fn write_length(&self) -> u32 {
        self.write_length
    }

    pub fn data_to_write(&self) -> &[u8] {
        &self.data_to_write
    }
}

#[derive(
    Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize, Clone,
)]
#[smb_byte_tag(value = 17)]
pub struct SMBWriteResponse {
    #[smb_skip(start = 2, length = 2)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 4))]
    bytes_written: u32,
    #[smb_skip(start = 8, length = 4)]
    remaining_bytes: PhantomData<Vec<u8>>,
    #[smb_skip(start = 12, length = 2)]
    write_channel_info_offset: PhantomData<Vec<u8>>,
    #[smb_skip(start = 14, length = 2)]
    write_channel_info_len: PhantomData<Vec<u8>>,
}

impl SMBWriteResponse {
    pub fn new(bytes_written: u32) -> Self {
        Self {
            reserved: PhantomData,
            bytes_written,
            remaining_bytes: PhantomData,
            write_channel_info_offset: PhantomData,
            write_channel_info_len: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBByteSize, SMBFromBytes, SMBToBytes};

    #[test]
    fn write_response_new_sets_bytes_written() {
        let resp = SMBWriteResponse::new(4096);
        assert_eq!(resp.bytes_written, 4096);
    }

    #[test]
    fn write_response_serialization_round_trip() {
        let resp = SMBWriteResponse::new(512);
        let bytes = resp.smb_to_bytes();
        assert_eq!(bytes.len(), resp.smb_byte_size());
        let (_, parsed) = SMBWriteResponse::smb_from_bytes(&bytes).unwrap();
        assert_eq!(resp, parsed);
    }

    #[test]
    fn write_request_accessors() {
        let bytes = {
            let mut buf = Vec::new();
            // struct_size (u16) = 49
            buf.extend_from_slice(&49u16.to_le_bytes());
            // data_offset (u16) — points past header (offset 2)
            let data_offset: u16 = 64 + 49; // header + struct
            buf.extend_from_slice(&data_offset.to_le_bytes());
            // write_length (u32) = 100 (offset 4)
            buf.extend_from_slice(&100u32.to_le_bytes());
            // write_offset (u64) = 200 (offset 8)
            buf.extend_from_slice(&200u64.to_le_bytes());
            // file_id: persistent (u64) + volatile (u64) (offset 16)
            buf.extend_from_slice(&5u64.to_le_bytes());
            buf.extend_from_slice(&15u64.to_le_bytes());
            // channel (u32) = 0 (offset 32..36 — but channel is at 36 per struct)
            // remaining_bytes (u32) = 0 (offset 36)
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            // channel_info_offset (u16) = 0, channel_info_length (u16) = 0 (offset 40..44)
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
            // flags (u32) = 0 (offset 44)
            buf.extend_from_slice(&0u32.to_le_bytes());
            // pad to data_offset - 64
            while buf.len() < (data_offset - 64) as usize {
                buf.push(0);
            }
            // data (100 bytes)
            buf.extend_from_slice(&[0xAB; 100]);
            buf
        };
        let (_, req) = SMBWriteRequest::smb_from_bytes(&bytes).unwrap();
        assert_eq!(req.write_length(), 100);
        assert_eq!(req.write_offset(), 200);
        assert_eq!(req.file_id().persistent(), 5);
        assert_eq!(req.file_id().volatile(), 15);
        assert_eq!(req.data_to_write().len(), 100);
    }
}
