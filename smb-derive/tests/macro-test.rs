extern crate smb_derive;

use smb_derive::SMBFromBytes;

#[derive(SMBFromBytes)]
struct Message {
    #[end = 0]
    test: u64
}

#[test]
fn it_works() {
    let msg = Message { test: 1};
}