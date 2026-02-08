use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

#[derive(
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Debug,
    SMBFromBytes,
    SMBToBytes,
    SMBByteSize,
    Clone
)]
#[smb_byte_tag(value = 4)]
#[smb_skip(start = 0, length = 4)]
pub struct SMBEmpty;

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBByteSize, SMBFromBytes, SMBToBytes};

    /// MS-SMB2 2.2.28/2.2.29: Echo request/response StructureSize = 4, no body.
    #[test]
    fn empty_structure_size() {
        let empty = SMBEmpty;
        let bytes = empty.smb_to_bytes();
        let structure_size = u16::from_le_bytes([bytes[0], bytes[1]]);
        assert_eq!(structure_size, 4, "Echo/Empty StructureSize must be 4");
    }

    #[test]
    fn empty_is_4_bytes() {
        let empty = SMBEmpty;
        assert_eq!(empty.smb_byte_size(), 4);
        assert_eq!(empty.smb_to_bytes().len(), 4);
    }

    #[test]
    fn empty_round_trip() {
        let empty = SMBEmpty;
        let bytes = empty.smb_to_bytes();
        let (remaining, parsed) = SMBEmpty::smb_from_bytes(&bytes).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(parsed, empty);
    }
}