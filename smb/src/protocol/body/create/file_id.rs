use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

#[derive(
    Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes,
)]
pub struct SMBFileId {
    #[smb_direct(start(fixed = 0))]
    pub persistent: u64,
    #[smb_direct(start(fixed = 8))]
    pub volatile: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBByteSize, SMBFromBytes, SMBToBytes};

    /// MS-SMB2 section 2.2.14.1: SMB2_FILEID is 16 bytes (Persistent u64 + Volatile u64)
    #[test]
    fn file_id_is_16_bytes() {
        let fid = SMBFileId {
            persistent: 0,
            volatile: 0,
        };
        assert_eq!(fid.smb_byte_size(), 16);
    }

    /// Persistent is at offset 0, Volatile at offset 8
    #[test]
    fn file_id_wire_layout() {
        let fid = SMBFileId {
            persistent: 0xDEAD,
            volatile: 0xBEEF,
        };
        let bytes = fid.smb_to_bytes();
        assert_eq!(bytes.len(), 16);
        let persistent = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let volatile = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        assert_eq!(persistent, 0xDEAD);
        assert_eq!(volatile, 0xBEEF);
    }

    #[test]
    fn file_id_round_trip() {
        let fid = SMBFileId {
            persistent: 42,
            volatile: 99,
        };
        let bytes = fid.smb_to_bytes();
        let (_, parsed) = SMBFileId::smb_from_bytes(&bytes).unwrap();
        assert_eq!(fid, parsed);
    }

    /// Per section 2.2.14.1, persistent and volatile are distinct fields.
    /// Verify they serialize independently.
    #[test]
    fn file_id_persistent_and_volatile_are_independent() {
        let a = SMBFileId {
            persistent: 1,
            volatile: 2,
        };
        let b = SMBFileId {
            persistent: 2,
            volatile: 1,
        };
        let bytes_a = a.smb_to_bytes();
        let bytes_b = b.smb_to_bytes();
        assert_ne!(bytes_a, bytes_b);
    }
}
