use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

macro_rules! impl_tag_for_ctx {
    ($body_struct: ty, $item: expr) => {
        impl $body_struct {
            pub fn tag(&self) -> &'static [u8] {
                $item
            }
        }
    };
}

macro_rules! create_ctx_smb_byte_size {
    ($body: expr) => {{
        let bytes = $body.smb_to_bytes();
        let tag = $body.tag();
        let wrapper = CreateContextWrapper {
            name: tag.to_vec(),
            reserved: PhantomData,
            data: bytes,
        };
        wrapper.smb_byte_size()
    }};
}

macro_rules! create_ctx_smb_from_bytes {
    ($enumType: expr, $bodyType: expr, $data: expr) => {
        {
            let (_, body) = $bodyType($data)?;
            Ok($enumType(body))
        }
    };
}

macro_rules! create_ctx_smb_to_bytes {
    ($body: expr, $tag: expr) => {
        {
            let bytes = $body.smb_to_bytes();
            let wrapper = CreateContextWrapper{
                data: bytes,
                reserved: PhantomData,
                name: $tag.to_vec(),
            };
            wrapper.smb_to_bytes()
        }
    };
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct CreateContextWrapper {
    #[smb_skip(start = 8, length = 4)]
    pub reserved: PhantomData<Vec<u8>>,
    #[smb_buffer(offset(inner(start = 4, num_type = "u16")), length(inner(start = 6, num_type = "u16")), order = 0)]
    pub name: Vec<u8>,
    #[smb_buffer(offset(inner(start = 10, num_type = "u16")), length(inner(start = 12, num_type = "u32")), order = 1)]
    pub data: Vec<u8>,
}

pub(crate) use create_ctx_smb_to_bytes;
pub(crate) use create_ctx_smb_from_bytes;
pub(crate) use create_ctx_smb_byte_size;
pub(crate) use impl_tag_for_ctx;