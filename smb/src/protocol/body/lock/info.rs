use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::lock::flags::SMBLockFlags;

#[derive(
    Debug,
    PartialEq,
    Eq,
    SMBByteSize,
    SMBToBytes,
    SMBFromBytes,
    Serialize,
    Deserialize,
    Clone
)]
pub struct SMBLockInfo {
    #[smb_direct(start(fixed = 0))]
    offset: u64,
    #[smb_direct(start(fixed = 8))]
    length: u64,
    #[smb_direct(start(fixed = 16))]
    flags: SMBLockFlags,
    #[smb_skip(start = 20, length = 4)]
    reserved: PhantomData<Vec<u8>>,
}