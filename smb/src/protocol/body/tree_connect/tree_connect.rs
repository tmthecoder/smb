use std::marker::PhantomData;

use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use smb_core::SMBFromBytes;
use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::tree_connect::{SMBAccessMask, SMBDirectoryAccessMask, SMBFilePipePrinterAccessMask, SMBTreeConnectBuffer};
use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

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

impl SMBTreeConnectResponse {
    pub fn default() -> Self {
        Self {
            maximal_access: SMBAccessMask::Directory(SMBDirectoryAccessMask::GENERIC_ALL),
            share_type: SMBShareType::Disk,
            reserved: PhantomData,
            share_flags: SMBShareFlags::NO_CACHING,
            capabilities: SMBTreeConnectCapabilities::empty(),
        }
    }

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

bitflags! {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct SMBTreeConnectFlags: u16 {
        const EXTENSION_PRESENT    = 0b100;
        const REDIRECT_TO_OWNER    = 0b10;
        const CLUSTER_RECONNECT    = 0b1;
        const RESERVED             = 0b0;
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

bitflags! {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    pub struct SMBShareFlags: u32 {
        const MANUAL_CACHING              = 0x000000;
        const AUTO_CACHING                = 0x000010;
        const VDO_CACHING                 = 0x000020;
        const NO_CACHING                  = 0x000030;
        const DFS                         = 0x000001;
        const DFS_ROOT                    = 0x000002;
        const RESTRICT_EXCLUSIVE_OPENS    = 0x000100;
        const FORCE_SHARED_DELETE         = 0x000200;
        const ALLOW_NAMESPACE_CACHING     = 0x000400;
        const ACCESS_BASED_DIRECTORY_ENUM = 0x000800;
        const FORCE_LEVEL_II_OPLOCK       = 0x001000;
        const ENABLE_HASH_V1              = 0x002000;
        const ENABLE_HASH_V2              = 0x004000;
        const ENCRYPT_DATA                = 0x008000;
        const IDENTITY_REMOTING           = 0x040000;
        const COMPRESS_DATA               = 0x100000;
        const ISOLATED_TRANSPORT          = 0x200000;
    }
}

impl Default for SMBShareFlags {
    fn default() -> Self {
        Self::MANUAL_CACHING
    }
}


bitflags! {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct SMBTreeConnectCapabilities: u32 {
        const DFS                     = 0x008;
        const CONTINUOUS_AVAILABILITY = 0x010;
        const SCALEOUT                = 0x020;
        const CLUSTER                 = 0x040;
        const ASYMMETRIC              = 0x080;
        const REDIRECT_TO_OWNER       = 0x100;
    }
}
impl_smb_byte_size_for_bitflag! { SMBTreeConnectFlags SMBShareFlags SMBTreeConnectCapabilities }
impl_smb_to_bytes_for_bitflag! { SMBTreeConnectFlags SMBShareFlags SMBTreeConnectCapabilities }
impl_smb_from_bytes_for_bitflag! { SMBTreeConnectFlags SMBShareFlags SMBTreeConnectCapabilities }
