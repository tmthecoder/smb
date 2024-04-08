use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::read::channel::SMBRWChannel;
use crate::protocol::body::write::flags::SMBWriteFlags;

mod flags;

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize)]
#[smb_byte_tag(49)]
pub struct SMBWriteRequest {
    #[smb_direct(start(fixed = 4))]
    length: u32,
    #[smb_direct(start(fixed = 8))]
    offset: u64,
    #[smb_direct(start(fixed = 16))]
    file_id: SMBFileId,
    #[smb_direct(start(fixed = 32))]
    channel: SMBRWChannel,
    #[smb_direct(start(fixed = 36))]
    remaining_bytes: u32,
    #[smb_direct(start(fixed = 44))]
    flags: SMBWriteFlags,
    #[smb_buffer(offset(inner(start = 40, num_type = "u16", subtract = 64)), length(inner(start = 42, num_type = "u16")))]
    channel_information: Vec<u8>,
    #[smb_buffer(offset(inner(start = 2, num_type = "u16", subtract = 64)), length(inner(start = 4, num_type = "u32")))]
    data_to_write: Vec<u8>,
}