use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBEnumFromBytes, SMBToBytes};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBEnumFromBytes, SMBByteSize, SMBToBytes, Clone)]
pub enum SMBAccessMask {
    #[smb_discriminator(value = 0x2, value = 0x3, value = 0x0)]
    #[smb_direct(start(fixed = 0))]
    FilePipePrinter(SMBFilePipePrinterAccessMask),
    #[smb_discriminator(value = 0x1)]
    #[smb_direct(start(fixed = 0))]
    Directory(SMBDirectoryAccessMask),
}

impl SMBAccessMask {
    pub fn raw(&self) -> u32 {
        match self {
            SMBAccessMask::FilePipePrinter(x) => x.bits(),
            SMBAccessMask::Directory(x) => x.bits()
        }
    }
    pub fn validate_print(&self) -> bool {
        match &self {
            SMBAccessMask::FilePipePrinter(access_mask) => access_mask.validate_print(),
            _ => false,
        }
    }

    pub fn includes_maximum_allowed(&self) -> bool {
        match self {
            SMBAccessMask::FilePipePrinter(x) => x.contains(SMBFilePipePrinterAccessMask::MAXIMUM_ALLOWED),
            SMBAccessMask::Directory(x) => x.contains(SMBDirectoryAccessMask::MAXIMUM_ALLOWED)
        }
    }

    pub fn includes_access_system_security(&self) -> bool {
        match self {
            SMBAccessMask::FilePipePrinter(x) => x.contains(SMBFilePipePrinterAccessMask::ACCESS_SYSTEM_SECURITY),
            SMBAccessMask::Directory(x) => x.contains(SMBDirectoryAccessMask::ACCESS_SYSTEM_SECURITY)
        }
    }

    pub fn access_no_connect_security(is_directory: bool) -> Self {
        match is_directory {
            true => Self::FilePipePrinter(SMBFilePipePrinterAccessMask::access_no_connect_security()),
            false => Self::Directory(SMBDirectoryAccessMask::access_no_connect_security()),
        }
    }

    pub fn from_desired_access(desired: &SMBAccessMask) -> Self {
        let mut mask = desired.clone();
        if mask.includes_maximum_allowed() {
            match mask {
                SMBAccessMask::FilePipePrinter(mut x) => x |= SMBFilePipePrinterAccessMask::GENERIC_ALL,
                SMBAccessMask::Directory(mut x) => x |= SMBDirectoryAccessMask::GENERIC_ALL
            };
        }

        if mask.includes_access_system_security() {
            match mask {
                SMBAccessMask::FilePipePrinter(mut x) => x |= SMBFilePipePrinterAccessMask::ACCESS_SYSTEM_SECURITY,
                SMBAccessMask::Directory(mut x) => x |= SMBDirectoryAccessMask::ACCESS_SYSTEM_SECURITY
            };
        }
        mask
    }
}

bitflags! {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
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

impl SMBFilePipePrinterAccessMask {
    pub fn validate_print(&self) -> bool {
        self.contains(SMBFilePipePrinterAccessMask::FILE_WRITE_DATA)
            || self.contains(SMBFilePipePrinterAccessMask::FILE_APPEND_DATA)
            || self.contains(SMBFilePipePrinterAccessMask::GENERIC_WRITE)
    }

    pub fn access_no_connect_security() -> Self {
        Self::FILE_READ_DATA | Self::FILE_WRITE_DATA | Self::FILE_APPEND_DATA | Self::FILE_READ_EA
            | Self::FILE_WRITE_EA | Self::FILE_DELETE_CHILD | Self::FILE_EXECUTE | Self::FILE_READ_ATTRIBUTES
            | Self::FILE_WRITE_ATTRIBUTES | Self::DELETE | Self::READ_CONTROL | Self::WRITE_DAC | Self::WRITE_OWNER
            | Self::SYNCHRONIZE
    }
}

bitflags! {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
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

impl SMBDirectoryAccessMask {
    pub fn access_no_connect_security() -> Self {
        Self::FILE_LIST_DIRECTORY | Self::FILE_ADD_FILE | Self::FILE_ADD_SUBDIRECTORY | Self::FILE_READ_EA
            | Self::FILE_WRITE_EA | Self::FILE_DELETE_CHILD | Self::FILE_TRAVERSE | Self::FILE_READ_ATTRIBUTES
            | Self::FILE_WRITE_ATTRIBUTES | Self::DELETE | Self::READ_CONTROL | Self::WRITE_DAC | Self::WRITE_OWNER
            | Self::SYNCHRONIZE
    }
}