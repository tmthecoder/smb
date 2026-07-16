use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::util::flags_helper::{
    impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag,
};

bitflags! {
    /// Mode flags for FILE_MODE_INFORMATION (MS-FSCC 2.4.26).
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
    pub struct FileModeFlags: u32 {
        const FILE_WRITE_THROUGH            = 0x00000002;
        const FILE_SEQUENTIAL_ONLY          = 0x00000004;
        const FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008;
        const FILE_SYNCHRONOUS_IO_ALERT     = 0x00000010;
        const FILE_SYNCHRONOUS_IO_NONALERT  = 0x00000020;
        const FILE_DELETE_ON_CLOSE          = 0x00001000;
    }
}

impl_smb_byte_size_for_bitflag! { FileModeFlags }
impl_smb_to_bytes_for_bitflag! { FileModeFlags }
impl_smb_from_bytes_for_bitflag! { FileModeFlags }

/// FILE_MODE_INFORMATION (MS-FSCC 2.4.26) — 4 bytes
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes,
)]
pub struct FileModeInformation {
    #[smb_direct(start(fixed = 0))]
    mode: FileModeFlags,
}

impl FileModeInformation {
    pub fn new(mode: FileModeFlags) -> Self {
        Self { mode }
    }

    pub fn mode(&self) -> FileModeFlags {
        self.mode
    }
}
