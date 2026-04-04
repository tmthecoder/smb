use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

#[derive(
    Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes,
)]
pub struct SMBFileId {
    #[smb_direct(start(fixed = 0))]
    persistent: u64,
    #[smb_direct(start(fixed = 8))]
    volatile: u64,
}

impl SMBFileId {
    pub fn new(persistent: u64, volatile: u64) -> Self {
        Self {
            persistent,
            volatile,
        }
    }

    pub fn persistent(&self) -> u64 {
        self.persistent
    }

    pub fn volatile(&self) -> u64 {
        self.volatile
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBByteSize, SMBFromBytes, SMBToBytes};

    /// MS-SMB2 section 2.2.14.1: SMB2_FILEID is 16 bytes (Persistent u64 + Volatile u64)
    #[test]
    fn file_id_is_16_bytes() {
        let fid = SMBFileId::new(0, 0);
        assert_eq!(fid.smb_byte_size(), 16);
    }

    /// Persistent is at offset 0, Volatile at offset 8
    #[test]
    fn file_id_wire_layout() {
        let fid = SMBFileId::new(0xDEAD, 0xBEEF);
        let bytes = fid.smb_to_bytes();
        assert_eq!(bytes.len(), 16);
        let persistent = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let volatile = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        assert_eq!(persistent, 0xDEAD);
        assert_eq!(volatile, 0xBEEF);
    }

    #[test]
    fn file_id_round_trip() {
        let fid = SMBFileId::new(42, 99);
        let bytes = fid.smb_to_bytes();
        let (_, parsed) = SMBFileId::smb_from_bytes(&bytes).unwrap();
        assert_eq!(fid, parsed);
    }

    /// Per section 2.2.14.1, persistent and volatile are distinct fields.
    /// Verify they serialize independently.
    #[test]
    fn file_id_persistent_and_volatile_are_independent() {
        let a = SMBFileId::new(1, 2);
        let b = SMBFileId::new(2, 1);
        let bytes_a = a.smb_to_bytes();
        let bytes_b = b.smb_to_bytes();
        assert_ne!(bytes_a, bytes_b);
    }

    #[test]
    fn file_id_getters() {
        let fid = SMBFileId::new(100, 200);
        assert_eq!(fid.persistent(), 100);
        assert_eq!(fid.volatile(), 200);
    }
}
