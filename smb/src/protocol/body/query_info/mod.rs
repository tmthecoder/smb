use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::query_info::flags::SMBQueryInfoFlags;
use crate::protocol::body::query_info::info_type::SMBInfoType;
use crate::protocol::body::query_info::security_information::SMBSecurityInformation;

mod flags;
mod info_type;
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
pub struct SMBQueryInfoResponse {
    #[smb_skip(start = 2, length = 6)]
    reserved: PhantomData<Vec<u8>>,
    // TODO make this a struct: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3b1b3598-a898-44ca-bfac-2dcae065247f
    #[smb_buffer(order = 0, offset(inner(start = 2, num_type = "u16", subtract = 64)), length(inner(start = 4, num_type = "u32")))]
    data: Vec<u8>,
}