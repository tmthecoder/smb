use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::read::channel::ReadChannel;
use crate::protocol::body::read::flags::SMBReadFlags;

mod flags;
mod channel;

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize)]
#[smb_byte_tag(49)]
pub struct SMBReadRequest {
    #[smb_direct(start(fixed = 3))]
    flags: SMBReadFlags,
    #[smb_direct(start(fixed = 4))]
    length: u32,
    #[smb_direct(start(fixed = 8))]
    offset: u64,
    #[smb_direct(start(fixed = 16))]
    file_id: SMBFileId,
    #[smb_direct(start(fixed = 32))]
    minimum_count: u32,
    #[smb_direct(start(fixed = 36))]
    channel: ReadChannel,
    #[smb_direct(start(fixed = 40))]
    remaining_bytes: u32,
    #[smb_buffer(offset(inner(start = 44, num_type = "u16", subtract = 64)), length(inner(start = 46, num_type = "u16")))]
    channel_information: Vec<u8>,
}