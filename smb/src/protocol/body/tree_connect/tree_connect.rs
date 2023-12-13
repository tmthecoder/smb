use std::marker::PhantomData;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use smb_core::SMBFromBytes;

use crate::protocol::body::tree_connect::SMBTreeConnectContext;
use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

// #[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBToBytes, SMBByteSize, SMBFromBytes)]
pub struct SMBTreeConnectRequest {
    // #[smb_direct(start(fixed = 2))]
    flags: SMBTreeConnectFlags,
    // #[smb_direct(start(fixed = 2))]
    buffer: SMBTreeConnectBuffer,
}

bitflags! {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct SMBTreeConnectFlags: u16 {
        const EXTENSION_PRESENT    = 0b100;
        const REDIRECT_TO_OWNER    = 0b10;
        const CLUSTER_RECONNECT    = 0b1;
        const RESERVED             = 0b0;
    }
}
// #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
enum SMBTreeConnectBuffer {
    Path(String),
    Extension(SMBTreeConnectExtension),
}

// impl SMBByteSize for SMBTreeConnectBuffer {
//     fn smb_byte_size(&self) -> usize {
//         match self {
//             Self::Path(path) => path.smb_byte_size(),
//             Self::Extension(extension) => extension.smb_byte_size()
//         }
//     }
// }
//
// impl SMBFromBytes for SMBTreeConnectBuffer {
//     fn smb_from_bytes(input: &[u8]) -> SMBParseResult<&[u8], Self> where Self: Sized {
//         match u16::smb_from_bytes(&input[2..]) & 0b0100 {
//             0b0100 => SMBTreeConnectExtension::smb_from_bytes(&input[8..])
//                 .map(|(remaining, result)| (remaining, Self::Extension(result))),
//             _ => {
//                 let (_, offset) = u16::smb_from_bytes(&input[4..]).map(|(r, i)| (r, i as usize))?;
//                 let (_, length) = u16::smb_from_bytes(&input[6..]).map(|(r, i)| (r, i as usize))?;
//                 let buffer = &input[(offset - 64)..(offset - 64 + length)];
//                 Ok((&input[(offset - 64 + length)..], Self::Path(String::from_utf8(buffer.to_vec()).map_err(|_| SMBError::ParseError("Invalid string".into()))?)))
//             },
//         }
//     }
// }

// #[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBToBytes, SMBByteSize, SMBFromBytes)]
struct SMBTreeConnectExtension {
    // #[smb_skip(start = 6, length = 2)]
    reserved: PhantomData<Vec<u8>>,
    // #[smb_vector(order = 1, offset(inner(start = 2, num_type = "u16", subtract = 64)), count(inner(start = 4, num_type = "u16")))]
    path_name: String,
    tree_connect_contexts: Vec<SMBTreeConnectContext>,
}

impl_smb_byte_size_for_bitflag! { SMBTreeConnectFlags }
impl_smb_to_bytes_for_bitflag! { SMBTreeConnectFlags }
impl_smb_from_bytes_for_bitflag! { SMBTreeConnectFlags }
