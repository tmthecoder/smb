use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::close::flags::SMBCloseFlags;
use crate::protocol::body::create::file_id::SMBFileId;

mod flags;

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