extern crate smb_derive;
extern crate smb_reader;

use smb_derive::SMBFromBytes;

#[repr(C)]
#[derive(SMBFromBytes)]
#[smb_byte_tag(value = 0xFE)]
#[smb_string_tag(value = "SMB")]
pub struct SMBSyncHeader {
    #[smb_direct(start = 8)]
    pub command: u16,
    #[smb_direct(start = 4)]
    channel_sequence: u32,
    #[smb_direct(start = 12)]
    flags: u32,
    #[smb_direct(start = 16)]
    next_command: u32,
    #[smb_direct(start = 20)]
    message_id: u64,
    #[smb_direct(start = 32)]
    tree_id: u32,
    #[smb_direct(start = 36)]
    session_id: u64,
    #[smb_buffer(offset(start = 0, type = "direct"), length(start = 0, type = "direct", subtract = - 16))]
    signature: Vec<u8>,
    #[smb_vector(order = 1, align = 8, count(start = 1, type = "u32"))]
    test: Vec<u32>,
}

#[test]
fn it_works() {
    SMBSyncHeader::smb_from_bytes(&[0]);
}