use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::change_notify::completion_filter::SMBCompletionFilter;
use crate::protocol::body::change_notify::flags::SMBChangeNotifyFlags;
use crate::protocol::body::create::file_id::SMBFileId;

mod flags;
mod completion_filter;

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize)]
#[smb_byte_tag(32)]
pub struct SMBChangeNotifyRequest {
    #[smb_direct(start(fixed = 2))]
    flags: SMBChangeNotifyFlags,
    #[smb_direct(start(fixed = 4))]
    output_buffer_length: u32,
    #[smb_direct(start(fixed = 8))]
    file_id: SMBFileId,
    #[smb_direct(start(fixed = 24))]
    completion_filter: SMBCompletionFilter,
    #[smb_skip(start = 28, length = 4)]
    reserved: PhantomData<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize)]
#[smb_byte_tag(17)]
pub struct SMBChangeNotifyResponse {
    #[smb_skip(start = 2, length = 6)]
    reserved: PhantomData<Vec<u8>>,
    // TODO make this into a vector of FILE_NOTIFY_INFO structs: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/14f9d050-27b2-49df-b009-54e08e8bf7b5
    #[smb_buffer(order = 0, offset(inner(start = 2, num_type = "u16", subtract = 64)), length(inner(start = 4, num_type = "u32")))]
    data: Vec<u8>,
}