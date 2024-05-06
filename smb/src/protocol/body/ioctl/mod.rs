use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::ioctl::flags::SMBIoCtlRequestFlags;
use crate::protocol::body::ioctl::method::SMBIoCtlMethod;

mod flags;
mod method;

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize)]
#[smb_byte_tag(57)]
pub struct SMBIoCtlRequest {
    #[smb_skip(start = 2, length = 2)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 4))]
    ctl_code: u32,
    #[smb_direct(start(fixed = 8))]
    file_id: SMBFileId,
    #[smb_direct(start(fixed = 32))]
    max_input_response: u32,
    #[smb_direct(start(fixed = 44))]
    max_output_response: u32,
    #[smb_direct(start(fixed = 48))]
    flags: SMBIoCtlRequestFlags,
    #[smb_skip(start = 52, length = 4)]
    reserved2: PhantomData<Vec<u8>>,
    #[smb_enum(start(inner(start = 24, num_type = "u32")), discriminator(inner(start = 4, num_type = "u32")))]
    input_method: SMBIoCtlMethod,
}

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize)]
#[smb_byte_tag(49)]
pub struct SMBIoCtlResponse {
    #[smb_skip(start = 2, length = 2)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 4))]
    ctl_code: u32,
    #[smb_direct(start(fixed = 8))]
    file_id: SMBFileId,
    #[smb_skip(start = 40, length = 4)]
    flags: PhantomData<Vec<u8>>,
    #[smb_skip(start = 44, length = 4)]
    reserved2: PhantomData<Vec<u8>>,
    #[smb_enum(start(inner(start = 30, num_type = "u32")), discriminator(inner(start = 4, num_type = "u32")))]
    input_method: SMBIoCtlMethod,
}