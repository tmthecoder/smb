use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::close::flags::SMBCloseFlags;
use crate::protocol::body::create::file_attributes::SMBFileAttributes;
use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::filetime::FileTime;

pub mod flags;

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
#[smb_byte_tag(value = 24)]
pub struct SMBCloseRequest {
    #[smb_direct(start(fixed = 2))]
    flags: SMBCloseFlags,
    #[smb_skip(start = 4, length = 4)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 8))]
    file_id: SMBFileId,
}

impl SMBCloseRequest {
    pub fn flags(&self) -> SMBCloseFlags {
        self.flags
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
#[smb_byte_tag(value = 60)]
pub struct SMBCloseResponse {
    #[smb_direct(start(fixed = 2))]
    flags: SMBCloseFlags,
    #[smb_skip(start = 4, length = 4)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 8))]
    creation_time: FileTime,
    #[smb_direct(start(fixed = 16))]
    last_access_time: FileTime,
    #[smb_direct(start(fixed = 24))]
    last_write_time: FileTime,
    #[smb_direct(start(fixed = 32))]
    change_time: FileTime,
    #[smb_direct(start(fixed = 40))]
    allocation_size: u64,
    #[smb_direct(start(fixed = 48))]
    end_of_file: u64,
    #[smb_direct(start(fixed = 56))]
    file_attributes: SMBFileAttributes,
}

impl SMBCloseResponse {
    pub fn from_metadata(metadata: &crate::server::share::SMBFileMetadata, attributes: SMBFileAttributes) -> Self {
        Self {
            flags: SMBCloseFlags::POSTQUERY_ATTRIB,
            reserved: PhantomData,
            creation_time: metadata.creation_time.clone(),
            last_access_time: metadata.last_access_time.clone(),
            last_write_time: metadata.last_write_time.clone(),
            change_time: metadata.last_modification_time.clone(),
            allocation_size: metadata.allocated_size,
            end_of_file: metadata.actual_size,
            file_attributes: attributes,
        }
    }

    pub fn empty() -> Self {
        Self {
            flags: SMBCloseFlags::empty(),
            reserved: PhantomData,
            creation_time: FileTime::zero(),
            last_access_time: FileTime::zero(),
            last_write_time: FileTime::zero(),
            change_time: FileTime::zero(),
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: SMBFileAttributes::empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBByteSize, SMBToBytes, SMBFromBytes};

    #[test]
    fn close_response_empty_has_zero_fields() {
        let resp = SMBCloseResponse::empty();
        assert_eq!(resp.flags, SMBCloseFlags::empty());
        assert_eq!(resp.allocation_size, 0);
        assert_eq!(resp.end_of_file, 0);
        assert_eq!(resp.file_attributes, SMBFileAttributes::empty());
    }

    #[test]
    fn close_response_empty_serialization_round_trip() {
        let resp = SMBCloseResponse::empty();
        let bytes = resp.smb_to_bytes();
        assert_eq!(bytes.len(), resp.smb_byte_size());
        let (_, parsed) = SMBCloseResponse::smb_from_bytes(&bytes).unwrap();
        assert_eq!(resp, parsed);
    }

    #[test]
    fn close_response_from_metadata_sets_postquery_flag() {
        use crate::server::share::SMBFileMetadata;
        let metadata = SMBFileMetadata {
            creation_time: FileTime::from_unix(1700000000),
            last_access_time: FileTime::from_unix(1700000100),
            last_write_time: FileTime::from_unix(1700000200),
            last_modification_time: FileTime::from_unix(1700000300),
            allocated_size: 4096,
            actual_size: 1024,
        };
        let resp = SMBCloseResponse::from_metadata(&metadata, SMBFileAttributes::NORMAL);
        assert!(resp.flags.contains(SMBCloseFlags::POSTQUERY_ATTRIB));
        assert_eq!(resp.allocation_size, 4096);
        assert_eq!(resp.end_of_file, 1024);
        assert_eq!(resp.file_attributes, SMBFileAttributes::NORMAL);
    }

    #[test]
    fn close_response_from_metadata_serialization_round_trip() {
        use crate::server::share::SMBFileMetadata;
        let metadata = SMBFileMetadata {
            creation_time: FileTime::from_unix(1700000000),
            last_access_time: FileTime::from_unix(1700000100),
            last_write_time: FileTime::from_unix(1700000200),
            last_modification_time: FileTime::from_unix(1700000300),
            allocated_size: 8192,
            actual_size: 2048,
        };
        let resp = SMBCloseResponse::from_metadata(&metadata, SMBFileAttributes::ARCHIVE);
        let bytes = resp.smb_to_bytes();
        assert_eq!(bytes.len(), resp.smb_byte_size());
        let (_, parsed) = SMBCloseResponse::smb_from_bytes(&bytes).unwrap();
        assert_eq!(resp, parsed);
    }

    #[test]
    fn close_request_accessors() {
        let file_id = SMBFileId { persistent: 42, volatile: 99 };
        let bytes = {
            let mut buf = Vec::new();
            // struct_size (u16) = 24
            buf.extend_from_slice(&24u16.to_le_bytes());
            // flags (u16) = POSTQUERY_ATTRIB = 0x0001
            buf.extend_from_slice(&1u16.to_le_bytes());
            // reserved (4 bytes)
            buf.extend_from_slice(&[0u8; 4]);
            // file_id: persistent (u64) + volatile (u64)
            buf.extend_from_slice(&42u64.to_le_bytes());
            buf.extend_from_slice(&99u64.to_le_bytes());
            buf
        };
        let (_, req) = SMBCloseRequest::smb_from_bytes(&bytes).unwrap();
        assert_eq!(req.file_id().persistent, file_id.persistent);
        assert_eq!(req.file_id().volatile, file_id.volatile);
        assert!(req.flags().contains(SMBCloseFlags::POSTQUERY_ATTRIB));
    }
}