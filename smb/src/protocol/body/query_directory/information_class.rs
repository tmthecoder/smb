use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, SMBFromBytes, SMBToBytes, SMBByteSize, TryFromPrimitive, Serialize, Deserialize)]
pub enum SMBInformationClass {
    FileDirectoryInformation = 0x1,
    FullFileificateInformation = 0x2,
    FileIdFullDirectoryInformation = 0x26,
    FileBothDirectoryInformation = 0x03,
    FileIdBothDirectoryInformation = 0x25,
    FileNamesInformation = 0x0C,
    FileIdExtdDirectoryInformation = 0x3C,
    // Must never be used and ignored on receipt
    FileInformationClassReserved = 0x64,
}