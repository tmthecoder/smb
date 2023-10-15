use std::marker::PhantomData;

use bitflags::bitflags;

use crate::protocol::body::tree_connect::SMBTreeConnectContext;

pub struct SMBTreeConnectRequest {
    flags: SMBTreeConnectFlags,
    buffer: SMBTreeConnectBuffer,
}


bitflags! {
    struct SMBTreeConnectFlags: u16 {
        const EXTENSION_PRESENT    = 0b100;
        const REDIRECT_TO_OWNER    = 0b10;
        const CLUSTER_RECONNECT    = 0b1;
    }
}

enum SMBTreeConnectBuffer {
    Path(String),
    Extension(SMBTreeConnectExtension),
}

struct SMBTreeConnectExtension {
    reserved: PhantomData<Vec<u8>>,
    path_name: String,
    tree_connect_contexts: Vec<SMBTreeConnectContext>,
}