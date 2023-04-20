extern crate smb_core;
extern crate smb_derive;

use smb_core::SMBFromBytes;
use smb_derive::{SMBByteSize, SMBFromBytes};

#[derive(SMBFromBytes, SMBByteSize)]
#[smb_byte_tag(value = 0xFE, order = 0)]
#[smb_string_tag(value = "SMB", order = 1)]
pub struct SMBSyncHeader {
    #[smb_direct(start = 8, length = 2)]
    pub command: u16,
    #[smb_direct(start = 4, length = 4)]
    channel_sequence: u32,
    #[smb_direct(start = 12, length = 4)]
    flags: u32,
    #[smb_direct(start = 16, length = 4)]
    next_command: u32,
    #[smb_direct(start = 20, length = 8)]
    message_id: u64,
    #[smb_direct(start = 32, length = 4)]
    tree_id: u32,
    #[smb_direct(start = 36, length = 8)]
    session_id: u64,
    #[smb_buffer(offset(start = 44, length = 1), length(start = 45, length = 15))]
    signature: [u8; 16],
}

#[test]
fn it_works() {
    SMBSyncHeader::smb_from_bytes(&[0]);
}