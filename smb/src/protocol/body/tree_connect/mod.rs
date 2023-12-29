use std::marker::PhantomData;

use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::tree_connect::access_mask::{SMBAccessMask, SMBDirectoryAccessMask, SMBFilePipePrinterAccessMask};
use crate::protocol::body::tree_connect::buffer::SMBTreeConnectBuffer;
use crate::protocol::body::tree_connect::capabilities::SMBTreeConnectCapabilities;
use crate::protocol::body::tree_connect::context::{LuidAttr, SidAttr};
use crate::protocol::body::tree_connect::flags::{SMBShareFlags, SMBTreeConnectFlags};
use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

pub mod context;
pub mod buffer;
pub mod access_mask;
pub mod flags;
pub mod capabilities;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBByteSize, SMBFromBytes, SMBToBytes)]
#[smb_byte_tag(value = 09)]
pub struct SMBTreeConnectRequest {
    #[smb_direct(start(fixed = 2))]
    flags: SMBTreeConnectFlags,
    #[smb_enum(start(fixed = 4), discriminator(inner(start = 3, num_type = "u8")))]
    buffer: SMBTreeConnectBuffer,
}

impl SMBTreeConnectRequest {
    pub fn path(&self) -> &str {
        self.buffer.path()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBByteSize, SMBFromBytes, SMBToBytes)]
#[smb_byte_tag(value = 16)]
pub struct SMBTreeConnectResponse {
    #[smb_direct(start(fixed = 2))]
    share_type: SMBShareType,
    #[smb_skip(start = 3, length = 1)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 4))]
    share_flags: SMBShareFlags,
    #[smb_direct(start(fixed = 8))]
    capabilities: SMBTreeConnectCapabilities,
    #[smb_enum(start(fixed = 12), discriminator(inner(start = 2, num_type = "u8")))]
    maximal_access: SMBAccessMask,
}

impl Default for SMBTreeConnectResponse {
    fn default() -> Self {
        Self {
            maximal_access: SMBAccessMask::Directory(SMBDirectoryAccessMask::GENERIC_ALL),
            share_type: SMBShareType::Disk,
            reserved: PhantomData,
            share_flags: SMBShareFlags::NO_CACHING,
            capabilities: SMBTreeConnectCapabilities::empty(),
        }
    }
}

impl SMBTreeConnectResponse {
    pub fn IPC() -> Self {
        Self {
            maximal_access: SMBAccessMask::FilePipePrinter(SMBFilePipePrinterAccessMask::from_bits_truncate(2032127)),
            share_type: SMBShareType::Pipe,
            reserved: PhantomData,
            share_flags: SMBShareFlags::NO_CACHING,
            capabilities: SMBTreeConnectCapabilities::empty(),
        }
    }
}

#[repr(u8)]
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Copy, Clone, SMBByteSize, SMBFromBytes, SMBToBytes, TryFromPrimitive)]
pub enum SMBShareType {
    Disk = 0x01,
    Pipe,
    Print,
}

impl Default for SMBShareType {
    fn default() -> Self {
        Self::Disk
    }
}

impl_smb_byte_size_for_bitflag! {
    SMBTreeConnectFlags
    SMBShareFlags
    SMBTreeConnectCapabilities
    LuidAttr
    SidAttr
    SMBFilePipePrinterAccessMask
    SMBDirectoryAccessMask
}
impl_smb_to_bytes_for_bitflag! {
    SMBTreeConnectFlags
    SMBShareFlags
    SMBTreeConnectCapabilities
    LuidAttr
    SidAttr
    SMBFilePipePrinterAccessMask
    SMBDirectoryAccessMask
}
impl_smb_from_bytes_for_bitflag! {
    SMBTreeConnectFlags
    SMBShareFlags
    SMBTreeConnectCapabilities
    LuidAttr
    SidAttr
    SMBFilePipePrinterAccessMask
    SMBDirectoryAccessMask
}
