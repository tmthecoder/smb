use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

/// FILE_FS_SIZE_INFORMATION (MS-FSCC 2.5.8) — 24 bytes
///
/// Returned for QueryInfo requests with info type SMB2_0_INFO_FILESYSTEM
/// and information class FileFsSizeInformation (3). Sizes are expressed in
/// allocation units of `sectors_per_allocation_unit * bytes_per_sector`.
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes,
)]
pub struct FileFsSizeInformation {
    #[smb_direct(start(fixed = 0))]
    total_allocation_units: u64,
    #[smb_direct(start(fixed = 8))]
    available_allocation_units: u64,
    #[smb_direct(start(fixed = 16))]
    sectors_per_allocation_unit: u32,
    #[smb_direct(start(fixed = 20))]
    bytes_per_sector: u32,
}

impl FileFsSizeInformation {
    pub fn new(
        total_allocation_units: u64,
        available_allocation_units: u64,
        sectors_per_allocation_unit: u32,
        bytes_per_sector: u32,
    ) -> Self {
        Self {
            total_allocation_units,
            available_allocation_units,
            sectors_per_allocation_unit,
            bytes_per_sector,
        }
    }

    pub fn total_allocation_units(&self) -> u64 {
        self.total_allocation_units
    }
    pub fn available_allocation_units(&self) -> u64 {
        self.available_allocation_units
    }
    pub fn sectors_per_allocation_unit(&self) -> u32 {
        self.sectors_per_allocation_unit
    }
    pub fn bytes_per_sector(&self) -> u32 {
        self.bytes_per_sector
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBByteSize, SMBFromBytes, SMBToBytes};

    #[test]
    fn fs_size_information_is_24_bytes() {
        let info = FileFsSizeInformation::new(1 << 28, 1 << 27, 8, 512);
        assert_eq!(info.smb_byte_size(), 24);
    }

    #[test]
    fn fs_size_information_round_trip() {
        let info = FileFsSizeInformation::new(1 << 28, 1 << 27, 8, 512);
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 24);
        let (_, parsed) = FileFsSizeInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn fs_size_information_wire_layout() {
        let info = FileFsSizeInformation::new(100, 50, 8, 512);
        let bytes = info.smb_to_bytes();
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 100);
        assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 50);
        assert_eq!(u32::from_le_bytes(bytes[16..20].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(bytes[20..24].try_into().unwrap()), 512);
    }
}
