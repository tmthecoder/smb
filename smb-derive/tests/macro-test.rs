extern crate smb_core;
extern crate smb_derive;

use std::marker::PhantomData;

use smb_core::SMBFromBytes;
use smb_derive::{SMBByteSize, SMBFromBytes};

#[derive(Debug, Eq, PartialEq, Clone, SMBByteSize, SMBFromBytes)]
#[smb_byte_tag(value = 0xFE, order = 0)]
#[smb_string_tag(value = "SMB", order = 1)]
#[smb_byte_tag(value = 64, order = 2)]
pub struct PreAuthIntegrityCapabilities {
    #[smb_direct(start = 0)]
    pid_high: u16,
    #[smb_direct(start = 2)]
    signature: u64,
    #[smb_skip(start = 2, length = 10)]
    s2: PhantomData<Vec<u8>>,
    #[smb_vector(order = 4, count(start = 4, num_type = "u16"))]
    s3: Vec<u8>,
}

#[repr(u16)]
#[derive(
Debug, Eq, PartialEq, Copy, Clone, Ord, PartialOrd, SMBFromBytes, SMBByteSize
)]
pub enum HashAlgorithm {
    SHA512 = 0x01,
}

impl TryFrom<u16> for HashAlgorithm {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(HashAlgorithm::SHA512)
    }
}

#[test]
fn it_works() {
    SMBSyncHeader::smb_from_bytes(&[0]);
}