use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBEnumFromBytes, SMBFromBytes, SMBToBytes};

use crate::protocol::body::tree_connect::context::SMBTreeConnectContext;

#[derive(
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Debug,
    SMBEnumFromBytes,
    SMBByteSize,
    SMBToBytes,
    Clone
)]
pub enum SMBTreeConnectBuffer {
    #[smb_discriminator(value = 0x0)]
    #[smb_string(order = 0, start(inner(start = 0, num_type = "u16", subtract = 68)), length(inner(start = 2, num_type = "u16")), underlying = "u16")]
    Path(String),
    #[smb_direct(start(fixed = 0))]
    #[smb_discriminator(value = 0x1)]
    Extension(SMBTreeConnectExtension),
}

impl SMBTreeConnectBuffer {
    pub fn share(&self) -> &str {
        let path_str = match self {
            SMBTreeConnectBuffer::Path(x) => x,
            SMBTreeConnectBuffer::Extension(x) => &x.path_name
        };
        let idx = path_str.rfind('\\');
        smb_core::logging::trace!(?idx, "parsing share name from path");
        if let Some(idx) = idx {
            &path_str[(idx + 1)..]
        } else {
            path_str
        }
    }
}

#[derive(
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Debug,
    SMBByteSize,
    SMBFromBytes,
    SMBToBytes,
    Clone
)]
pub struct SMBTreeConnectExtension {
    #[smb_skip(start = 12, length = 2)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_string(order = 1, start(inner(start = 2, num_type = "u16", subtract = 64)), length = "null_terminated", underlying = "u16")]
    path_name: String,
    #[smb_vector(order = 2, count(inner(start = 10, num_type = "u16")), offset(inner(start = 6, num_type = "u32", subtract = 64)))]
    tree_connect_contexts: Vec<SMBTreeConnectContext>,
}