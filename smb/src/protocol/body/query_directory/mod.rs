use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::query_directory::flags::SMBQueryDirectoryFlags;
use crate::protocol::body::query_directory::information_class::SMBInformationClass;

mod information_class;
mod flags;

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize)]
#[smb_byte_tag(33)]
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
    #[smb_string(order = 0, start(inner(start = 24, num_type = "u16", subtract = 64)), length(inner(start = 26, num_type = "u16")), underlying = "u16")]
    search_pattern: String,
}

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize)]
#[smb_byte_tag(9)]
pub struct SMBQueryDirectoryResponse {
    #[smb_skip(start = 0, length = 8)]
    output_info: PhantomData<Vec<u8>>,
    // TODO make this a file directory class https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/4f75351b-048c-4a0c-9ea3-addd55a71956
    #[smb_buffer(offset(inner(start = 2, num_type = "u16", subtract = 64)), length(inner(start = 4, num_type = "u32")))]
    buffer: Vec<u8>,
}