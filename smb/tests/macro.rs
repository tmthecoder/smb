extern crate smb_derive;
extern crate smb_reader;

use smb_core::SMBFromBytes;
use smb_derive::SMBFromBytes;

#[repr(C)]
#[derive(SMBFromBytes)]
#[byte_tag(value = 0xFE)]
#[string_tag(value = "SMB")]
pub struct SMBSyncHeader {
    #[direct(start = 8)]
    pub command: u16,
    #[direct(start = 4)]
    channel_sequence: u32,
    #[direct(start = 12)]
    flags: u32,
    #[direct(start = 16)]
    next_command: u32,
    #[direct(start = 20)]
    message_id: u64,
    #[direct(start = 32)]
    tree_id: u32,
    #[direct(start = 36)]
    session_id: u64,
    #[buffer(offset(start = 0, type = "direct"), length(start = 0, type = "u16"))]
    signature: Vec<u8>,
    #[vector(order = 1, align = 8, count(start = 1, type = "u32"))]
    test: Vec<u32>,
}

#[test]
fn it_works() {
    SMBSyncHeader::parse_smb_message(&[0]);
}