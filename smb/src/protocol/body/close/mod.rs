use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::close::flags::SMBCloseFlags;
use crate::protocol::body::create::file_attributes::SMBFileAttributes;
use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::filetime::FileTime;

mod flags;
mod file_attributes;

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize)]
#[smb_byte_tag(24)]
pub struct SMBCloseRequest {
    #[smb_direct(start(fixed = 2))]
    flags: SMBCloseFlags,
    #[smb_skip(start = 4, length = 4)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 8))]
    file_id: SMBFileId,
}

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize)]
#[smb_byte_tag(60)]
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