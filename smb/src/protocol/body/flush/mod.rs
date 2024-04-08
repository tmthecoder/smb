use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::empty::SMBEmpty;

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize)]
#[smb_byte_tag(24)]
pub struct SMBFlushRequest {
    #[smb_skip(start = 2, length = 2)]
    reserved_1: PhantomData<Vec<u8>>,
    #[smb_skip(start = 4, length = 4)]
    reserved_2: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 8))]
    file_id: SMBFileId,
}

pub type SMBFlushResponse = SMBEmpty;