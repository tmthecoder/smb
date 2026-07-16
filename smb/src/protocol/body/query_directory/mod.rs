use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::query_directory::flags::SMBQueryDirectoryFlags;
use crate::protocol::body::query_directory::information_class::SMBInformationClass;

pub mod flags;
pub mod information_class;

#[derive(
    Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize, Clone,
)]
#[smb_byte_tag(value = 33)]
pub struct SMBQueryDirectoryRequest {
    #[smb_direct(start(fixed = 2))]
    information_class: SMBInformationClass,
    #[smb_direct(start(fixed = 3))]
    flags: SMBQueryDirectoryFlags,
    #[smb_direct(start(fixed = 4))]
    file_index: u32,
    #[smb_direct(start(fixed = 8))]
    file_id: SMBFileId,
    #[smb_direct(start(fixed = 28))]
    max_output_len: u32,
    #[smb_string(
        order = 0,
        start(inner(start = 24, num_type = "u16", subtract = 64)),
        length(inner(start = 26, num_type = "u16")),
        underlying = "u16"
    )]
    search_pattern: String,
}

impl SMBQueryDirectoryRequest {
    pub fn information_class(&self) -> SMBInformationClass {
        self.information_class
    }

    pub fn flags(&self) -> SMBQueryDirectoryFlags {
        self.flags
    }

    pub fn file_id(&self) -> &SMBFileId {
        &self.file_id
    }

    pub fn max_output_len(&self) -> u32 {
        self.max_output_len
    }

    pub fn search_pattern(&self) -> &str {
        &self.search_pattern
    }
}

/// QUERY_DIRECTORY response (MS-SMB2 §2.2.34): StructureSize (2, value 9),
/// OutputBufferOffset (2), OutputBufferLength (4), then the buffer of chained
/// directory information entries.
#[derive(
    Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize, Clone,
)]
#[smb_byte_tag(value = 9)]
pub struct SMBQueryDirectoryResponse {
    #[smb_skip(start = 2, length = 6)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_buffer(
        order = 0,
        offset(inner(start = 2, num_type = "u16", subtract = 64)),
        length(inner(start = 4, num_type = "u32"))
    )]
    buffer: Vec<u8>,
}

impl SMBQueryDirectoryResponse {
    pub fn new(buffer: Vec<u8>) -> Self {
        Self {
            reserved: PhantomData,
            buffer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBByteSize, SMBFromBytes, SMBToBytes};

    #[test]
    fn query_directory_response_round_trip() {
        let resp = SMBQueryDirectoryResponse::new(vec![0xAB; 112]);
        let bytes = resp.smb_to_bytes();
        assert_eq!(bytes.len(), resp.smb_byte_size());
        let (_, parsed) = SMBQueryDirectoryResponse::smb_from_bytes(&bytes).unwrap();
        assert_eq!(resp, parsed);
    }

    #[test]
    fn query_directory_response_empty_buffer_round_trip() {
        let resp = SMBQueryDirectoryResponse::new(vec![]);
        let bytes = resp.smb_to_bytes();
        let (_, parsed) = SMBQueryDirectoryResponse::smb_from_bytes(&bytes).unwrap();
        assert_eq!(resp, parsed);
    }

    #[test]
    fn query_directory_response_wire_layout() {
        let resp = SMBQueryDirectoryResponse::new(vec![0xCD; 10]);
        let bytes = resp.smb_to_bytes();
        // StructureSize = 9 at offset 0
        assert_eq!(u16::from_le_bytes(bytes[0..2].try_into().unwrap()), 9);
        // OutputBufferOffset at offset 2 = 72 (64-byte header + 8-byte fixed part)
        assert_eq!(u16::from_le_bytes(bytes[2..4].try_into().unwrap()), 72);
        // OutputBufferLength at offset 4 = 10
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 10);
        assert_eq!(&bytes[8..18], &[0xCD; 10]);
    }

    #[test]
    fn query_directory_request_accessors() {
        let pattern: Vec<u8> = "*".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let bytes = {
            let mut buf = Vec::new();
            // struct_size (u16) = 33
            buf.extend_from_slice(&33u16.to_le_bytes());
            // information_class (u8) = 0x25 (FileIdBothDirectoryInformation)
            buf.push(0x25);
            // flags (u8) = RESTART_SCANS
            buf.push(0x1);
            // file_index (u32)
            buf.extend_from_slice(&0u32.to_le_bytes());
            // file_id: persistent + volatile
            buf.extend_from_slice(&7u64.to_le_bytes());
            buf.extend_from_slice(&9u64.to_le_bytes());
            // file_name_offset (u16) = 64 (header) + 32 (fixed part)
            buf.extend_from_slice(&96u16.to_le_bytes());
            // file_name_length (u16)
            buf.extend_from_slice(&(pattern.len() as u16).to_le_bytes());
            // output_buffer_length (u32)
            buf.extend_from_slice(&65536u32.to_le_bytes());
            // search pattern ("*" UTF-16LE)
            buf.extend_from_slice(&pattern);
            buf
        };
        let (_, req) = SMBQueryDirectoryRequest::smb_from_bytes(&bytes).unwrap();
        assert_eq!(
            req.information_class(),
            SMBInformationClass::FileIdBothDirectoryInformation
        );
        assert!(req.flags().contains(SMBQueryDirectoryFlags::RESTART_SCANS));
        assert_eq!(req.file_id().persistent(), 7);
        assert_eq!(req.file_id().volatile(), 9);
        assert_eq!(req.max_output_len(), 65536);
        assert_eq!(req.search_pattern(), "*");
    }
}
