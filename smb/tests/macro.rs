extern crate smb_derive;
extern crate smb_reader;

use num_enum::TryFromPrimitive;

use smb_core::SMBFromBytes;
use smb_derive::SMBFromBytes;

#[repr(C)]
#[derive(SMBFromBytes)]
#[byte_tag(value = 0xFE)]
#[string_tag(value = "SMB")]
pub struct SMBSyncHeader {
    #[direct(start = 8, length = 2)]
    pub command: u16,
    #[direct(start = 4, length = 4)]
    channel_sequence: u32,
    #[direct(start = 12, length = 4)]
    flags: u32,
    #[direct(start = 16, length = 4)]
    next_command: u32,
    #[direct(start = 20, length = 8)]
    message_id: u64,
    #[direct(start = 32, length = 4)]
    tree_id: u32,
    #[direct(start = 36, length = 8)]
    session_id: u64,
    #[buffer(offset(start = 44, length = 1), length(start = 45, length = 15))]
    signature: Vec<u8>,
}

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, Clone, Copy, TryFromPrimitive, SMBFromBytes)]
pub enum SMBCommandCode {
    Negotiate = 0x0,
    SessionSetup,
    LogOff,
    TreeConnect,
    TreeDisconnect,
    Create,
    Close,
    Flush,
    Read,
    Write,
    Lock,
    IOCTL,
    Cancel,
    Echo,
    QueryDirectory,
    ChangeNotify,
    QueryInfo,
    SetInfo,
    OplockBreak,
    LegacyNegotiate,
}

#[test]
fn it_works() {
    // SMBSyncHeader::parse_smb_message(&[0]);

    println!("msg: {:?}", SMBCommandCode::parse_smb_message(&[1, 0]))
}