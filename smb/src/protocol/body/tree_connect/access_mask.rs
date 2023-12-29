use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBEnumFromBytes, SMBToBytes};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBEnumFromBytes, SMBByteSize, SMBToBytes)]
pub enum SMBAccessMask {
    #[smb_discriminator(value = 0x2, value = 0x3)]
    #[smb_direct(start(fixed = 0))]
    FilePipePrinter(SMBFilePipePrinterAccessMask),
    #[smb_discriminator(value = 0x1)]
    #[smb_direct(start(fixed = 0))]
    Directory(SMBDirectoryAccessMask),
}

bitflags! {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    pub struct SMBFilePipePrinterAccessMask: u32 {
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
    pub struct SMBDirectoryAccessMask: u32 {
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