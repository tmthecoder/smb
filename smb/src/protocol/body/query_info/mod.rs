use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::query_info::flags::SMBQueryInfoFlags;
use crate::protocol::body::query_info::info_type::SMBInfoType;
use crate::protocol::body::query_info::security_information::SMBSecurityInformation;

mod flags;
pub mod info_type;
mod security_information;

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
#[smb_byte_tag(value = 41)]
pub struct SMBQueryInfoRequest {
    #[smb_direct(start(fixed = 2))]
    info_type: SMBInfoType,
    #[smb_direct(start(fixed = 3))]
    file_info_class: u8,
    #[smb_direct(start(fixed = 4))]
    output_buffer_length: u32,
    #[smb_skip(start = 10, length = 2)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 16))]
    additional_information: SMBSecurityInformation,
    #[smb_direct(start(fixed = 20))]
    flags: SMBQueryInfoFlags,
    #[smb_direct(start(fixed = 24))]
    file_id: SMBFileId,
    #[smb_buffer(offset(inner(start = 8, num_type = "u16", subtract = 64)), length(inner(start = 12, num_type = "u32")))]
    buffer: Vec<u8>,
}

impl SMBQueryInfoRequest {
    pub fn info_type(&self) -> SMBInfoType {
        self.info_type
    }

    pub fn file_info_class(&self) -> u8 {
        self.file_info_class
    }

    pub fn output_buffer_length(&self) -> u32 {
        self.output_buffer_length
    }

    pub fn file_id(&self) -> &SMBFileId {
        &self.file_id
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
#[smb_byte_tag(value = 9)]
pub struct SMBQueryInfoResponse {
    #[smb_skip(start = 2, length = 6)]
    reserved: PhantomData<Vec<u8>>,
    // TODO make this a struct: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3b1b3598-a898-44ca-bfac-2dcae065247f
    #[smb_buffer(order = 0, offset(inner(start = 2, num_type = "u16", subtract = 64)), length(inner(start = 4, num_type = "u32")))]
    data: Vec<u8>,
}

impl SMBQueryInfoResponse {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            reserved: PhantomData,
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBByteSize, SMBToBytes, SMBFromBytes};

    #[test]
    fn query_info_response_new_sets_data() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let resp = SMBQueryInfoResponse::new(data.clone());
        assert_eq!(resp.data, data);
    }

    #[test]
    fn query_info_response_serialization_round_trip() {
        let resp = SMBQueryInfoResponse::new(vec![0xAA; 40]);
        let bytes = resp.smb_to_bytes();
        assert_eq!(bytes.len(), resp.smb_byte_size());
        let (_, parsed) = SMBQueryInfoResponse::smb_from_bytes(&bytes).unwrap();
        assert_eq!(resp, parsed);
    }

    #[test]
    fn query_info_response_empty_data_round_trip() {
        let resp = SMBQueryInfoResponse::new(vec![]);
        let bytes = resp.smb_to_bytes();
        let (_, parsed) = SMBQueryInfoResponse::smb_from_bytes(&bytes).unwrap();
        assert_eq!(resp, parsed);
    }

    #[test]
    fn query_info_request_accessors() {
        let bytes = {
            let mut buf = Vec::new();
            // struct_size (u16) = 41
            buf.extend_from_slice(&41u16.to_le_bytes());
            // info_type (u8) = 1 (File) per MS-SMB2
            buf.push(1);
            // file_info_class (u8) = 4 (FileBasicInformation)
            buf.push(4);
            // output_buffer_length (u32) = 4096
            buf.extend_from_slice(&4096u32.to_le_bytes());
            // input_buffer_offset (u16) = 0
            buf.extend_from_slice(&0u16.to_le_bytes());
            // reserved (u16) = 0
            buf.extend_from_slice(&0u16.to_le_bytes());
            // input_buffer_length (u32) = 0
            buf.extend_from_slice(&0u32.to_le_bytes());
            // additional_information (u32) = 0
            buf.extend_from_slice(&0u32.to_le_bytes());
            // flags (u32) = 0
            buf.extend_from_slice(&0u32.to_le_bytes());
            // file_id: persistent (u64) + volatile (u64)
            buf.extend_from_slice(&55u64.to_le_bytes());
            buf.extend_from_slice(&77u64.to_le_bytes());
            buf
        };
        let (_, req) = SMBQueryInfoRequest::smb_from_bytes(&bytes).unwrap();
        assert_eq!(req.info_type(), SMBInfoType::File);
        assert_eq!(req.file_info_class(), 4);
        assert_eq!(req.output_buffer_length(), 4096);
        assert_eq!(req.file_id().persistent, 55);
        assert_eq!(req.file_id().volatile, 77);
    }
}