use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use smb_core::error::SMBError;
use smb_core::{SMBByteSize, SMBFromBytes, SMBParseResult, SMBToBytes};
use smb_derive::{
    SMBByteSize as SMBByteSizeDerive, SMBFromBytes as SMBFromBytesDerive,
    SMBToBytes as SMBToBytesDerive,
};

/// Device alignment requirements (MS-FSCC 2.4.3).
///
/// Each value specifies the address boundary the device requires
/// for data transfers. For example, `Quad` means the device requires
/// 8-byte aligned addresses.
#[repr(u32)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, TryFromPrimitive)]
pub enum FileAlignmentRequirement {
    Byte = 0x00000000,
    Word = 0x00000001,
    Long = 0x00000003,
    Quad = 0x00000007,
    Octa = 0x0000000F,
    Align32 = 0x0000001F,
    Align64 = 0x0000003F,
    Align128 = 0x0000007F,
    Align256 = 0x000000FF,
    Align512 = 0x000001FF,
}

impl SMBByteSize for FileAlignmentRequirement {
    fn smb_byte_size(&self) -> usize {
        std::mem::size_of::<u32>()
    }
}

impl SMBFromBytes for FileAlignmentRequirement {
    fn smb_from_bytes(input: &[u8]) -> SMBParseResult<&[u8], Self>
    where
        Self: Sized,
    {
        u32::smb_from_bytes(input).map(|(remaining, val)| {
            let req = Self::try_from_primitive(val).map_err(SMBError::parse_error)?;
            Ok((remaining, req))
        })?
    }
}

impl SMBToBytes for FileAlignmentRequirement {
    fn smb_to_bytes(&self) -> Vec<u8> {
        (*self as u32).smb_to_bytes()
    }
}

/// FILE_ALIGNMENT_INFORMATION (MS-FSCC 2.4.3) — 4 bytes
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    SMBByteSizeDerive,
    SMBFromBytesDerive,
    SMBToBytesDerive,
)]
pub struct FileAlignmentInformation {
    #[smb_direct(start(fixed = 0))]
    alignment_requirement: FileAlignmentRequirement,
}

impl FileAlignmentInformation {
    pub fn new(alignment_requirement: FileAlignmentRequirement) -> Self {
        Self {
            alignment_requirement,
        }
    }

    pub fn alignment_requirement(&self) -> FileAlignmentRequirement {
        self.alignment_requirement
    }
}
