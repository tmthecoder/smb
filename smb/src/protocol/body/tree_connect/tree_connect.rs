use std::marker::PhantomData;

use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use smb_core::error::SMBError;
use smb_core::SMBFromBytes;
use smb_derive::{SMBByteSize, SMBEnumFromBytes, SMBFromBytes, SMBToBytes};

use crate::protocol::body::tree_connect::SMBTreeConnectContext;
use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBByteSize, SMBFromBytes)]
#[smb_byte_tag(value = 09)]
pub struct SMBTreeConnectRequest {
    #[smb_direct(start(fixed = 2))]
    flags: SMBTreeConnectFlags,
    #[smb_enum(start(fixed = 4), discriminator(inner(start = 3, num_type = "u8")))]
    buffer: SMBTreeConnectBuffer,
}

impl SMBTreeConnectRequest {
    pub fn path(&self) -> &str {
        match &self.buffer {
            SMBTreeConnectBuffer::Path(x) => x,
            SMBTreeConnectBuffer::Extension(x) => &x.path_name
        }
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
            share_type: SMBShareType::DISK,
            reserved: PhantomData,
            share_flags: SMBShareFlags::NO_CACHING,
            capabilities: SMBTreeConnectCapabilities::empty(),
        }
    }

    pub fn IPC() -> Self {
        Self {
            maximal_access: SMBAccessMask::FilePipePrinter(SMBFilePipePrinterAccessMask::from_bits_truncate(2032127)),
            share_type: SMBShareType::PIPE,
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
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBEnumFromBytes, SMBByteSize)]
enum SMBTreeConnectBuffer {
    #[smb_discriminator(value = 0x0)]
    #[smb_string(order = 0, start(inner(start = 0, num_type = "u16", subtract = 68)), length(inner(start = 2, num_type = "u16")), underlying = "u16")]
    Path(String),
    #[smb_direct(start(fixed = 0))]
    #[smb_discriminator(value = 0x1)]
    Extension(SMBTreeConnectExtension),
}

#[repr(u8)]
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Copy, Clone, SMBByteSize, SMBFromBytes, SMBToBytes, TryFromPrimitive)]
enum SMBShareType {
    DISK = 0x01,
    PIPE,
    PRINT,
}

bitflags! {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct SMBShareFlags: u32 {
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
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBEnumFromBytes, SMBByteSize, SMBToBytes)]
enum SMBAccessMask {
    #[smb_discriminator(value = 0x2, value = 0x3)]
    #[smb_direct(start(fixed = 0))]
    FilePipePrinter(SMBFilePipePrinterAccessMask),
    #[smb_discriminator(value = 0x1)]
    #[smb_direct(start(fixed = 0))]
    Directory(SMBDirectoryAccessMask),
}

bitflags! {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct SMBFilePipePrinterAccessMask: u32 {
        const FILE_READ_DATA         = 0x00000001;
        const FILE_WRITE_DATA        = 0x00000002;
        const FILE_APPEND_DATA       = 0x00000004;
        const FILE_READ_EA           = 0x00000008;
        const FILE_WRITE_EA          = 0x00000010;
        const FILE_DELETE_CHILD      = 0x00000040;
        const FILE_EXECUTE           = 0x00000020;
        const FILE_READ_ATTRIBUTES   = 0x00000080;
        const FILE_WRITE_ATTRIBUTES  = 0x00000100;
        const DELTE                  = 0x00010000;
        const READ_CONTROL           = 0x00020000;
        const WRITE_DAC              = 0x00040000;
        const WRITE_OWNER            = 0x00080000;
        const SYNCHRONIZE            = 0x00100000;
        const ACCESS_SYSTEM_SECURITY = 0x01000000;
        const MAXIMUM_ALLOWED        = 0x02000000;
        const GENERIC_ALL            = 0x10000000;
        const GENERIC_EXECUTE        = 0x20000000;
        const GENERIC_WRITE          = 0x40000000;
        const GENERIC_READ           = 0x80000000;
    }
}

bitflags! {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct SMBDirectoryAccessMask: u32 {
        const FILE_LIST_DIRECTORY    = 0x00000001;
        const FILE_ADD_FILE          = 0x00000002;
        const FILE_ADD_SUBDIRECTORY  = 0x00000004;
        const FILE_READ_EA           = 0x00000008;
        const FILE_WRITE_EA          = 0x00000010;
        const FILE_TRAVERSE          = 0x00000020;
        const FILE_DELETE_CHILD      = 0x00000040;
        const FILE_READ_ATTRIBUTES   = 0x00000080;
        const FILE_WRITE_ATTRIBUTES  = 0x00000100;
        const DELTE                  = 0x00010000;
        const READ_CONTROL           = 0x00020000;
        const WRITE_DAC              = 0x00040000;
        const WRITE_OWNER            = 0x00080000;
        const SYNCHRONIZE            = 0x00100000;
        const ACCESS_SYSTEM_SECURITY = 0x01000000;
        const MAXIMUM_ALLOWED        = 0x02000000;
        const GENERIC_ALL            = 0x10000000;
        const GENERIC_EXECUTE        = 0x20000000;
        const GENERIC_WRITE          = 0x40000000;
        const GENERIC_READ           = 0x80000000;
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBByteSize, SMBFromBytes)]
struct SMBTreeConnectExtension {
    #[smb_skip(start = 12, length = 2)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_string(order = 1, start(inner(start = 2, num_type = "u16", subtract = 64)), length = "null_terminated", underlying = "u16")]
    path_name: String,
    #[smb_vector(order = 2, count(inner(start = 10, num_type = "u16")), offset(inner(start = 6, num_type = "u32", subtract = 64)))]
    tree_connect_contexts: Vec<SMBTreeConnectContext>,
}

impl_smb_byte_size_for_bitflag! { SMBTreeConnectFlags SMBShareFlags SMBTreeConnectCapabilities SMBFilePipePrinterAccessMask SMBDirectoryAccessMask }
impl_smb_to_bytes_for_bitflag! { SMBTreeConnectFlags SMBShareFlags SMBTreeConnectCapabilities SMBFilePipePrinterAccessMask SMBDirectoryAccessMask }
impl_smb_from_bytes_for_bitflag! { SMBTreeConnectFlags SMBShareFlags SMBTreeConnectCapabilities SMBFilePipePrinterAccessMask SMBDirectoryAccessMask }
