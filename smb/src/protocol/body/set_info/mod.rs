use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::set_info::info_type::SMBInfoType;

mod info_type;

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize)]
#[smb_byte_tag(value = 33)]
pub struct SMBSetInfoRequest {
    #[smb_direct(start(fixed = 3))]
    info_type: SMBInfoType,
    #[smb_skip(start = 10, length = 2)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 12))]
    additional_information: u32,
    #[smb_direct(start(fixed = 16))]
    file_id: SMBFileId,
    #[smb_buffer(offset(inner(start = 8, num_type = "u16", subtract = 64)), length(inner(start = 4, num_type = "u32")))]
    buffer: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize)]
#[smb_byte_tag(value = 2)]
pub struct SMBSetInfoResponse {
    #[smb_skip(start = 0, length = 1)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_skip(start = 1, length = 1)]
    reserved2: PhantomData<Vec<u8>>,
}