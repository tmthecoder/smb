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