use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

/// ACCESS_MASK flags for FILE_ACCESS_INFORMATION (MS-FSCC 2.4.1).
///
/// These are the same ACCESS_MASK values defined in [MS-DTYP] §2.4.3 /
/// [MS-SMB2] §2.2.13.1, representing the access rights granted on the open.
bitflags! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
    pub struct FileAccessFlags: u32 {
        const FILE_READ_DATA         = 0x00000001;
        const FILE_WRITE_DATA        = 0x00000002;
        const FILE_APPEND_DATA       = 0x00000004;
        const FILE_READ_EA           = 0x00000008;
        const FILE_WRITE_EA          = 0x00000010;
        const FILE_EXECUTE           = 0x00000020;
        const FILE_DELETE_CHILD      = 0x00000040;
        const FILE_READ_ATTRIBUTES   = 0x00000080;
        const FILE_WRITE_ATTRIBUTES  = 0x00000100;
        const DELETE                  = 0x00010000;
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

impl_smb_byte_size_for_bitflag! { FileAccessFlags }
impl_smb_to_bytes_for_bitflag! { FileAccessFlags }
impl_smb_from_bytes_for_bitflag! { FileAccessFlags }

/// FILE_ACCESS_INFORMATION (MS-FSCC 2.4.1) — 4 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileAccessInformation {
    #[smb_direct(start(fixed = 0))]
    access_flags: FileAccessFlags,
}

impl FileAccessInformation {
    pub fn new(access_flags: FileAccessFlags) -> Self {
        Self { access_flags }
    }

    pub fn access_flags(&self) -> FileAccessFlags { self.access_flags }
}
