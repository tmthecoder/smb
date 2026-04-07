use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

/// FILE_NAME_INFORMATION (MS-FSCC 2.4.28) — variable length
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes,
)]
pub struct FileNameInformation {
    #[smb_direct(start(fixed = 0))]
    file_name_length: u32,
    #[smb_string(
        order = 0,
        start(fixed = 4),
        length(inner(start = 0, num_type = "u32")),
        underlying = "u16"
    )]
    file_name: String,
}

impl FileNameInformation {
    pub fn from_name(file_name: String) -> Self {
        let file_name_length = (file_name.encode_utf16().count() * 2) as u32;
        Self {
            file_name_length,
            file_name,
        }
    }

    pub fn file_name_length(&self) -> u32 {
        self.file_name_length
    }
    pub fn file_name(&self) -> &str {
        &self.file_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBFromBytes, SMBToBytes};

    #[test]
    fn from_name_computes_utf16_byte_length() {
        let info = FileNameInformation::from_name("test.txt".into());
        // "test.txt" = 8 UTF-16 code units × 2 bytes = 16
        assert_eq!(info.file_name_length(), 16);
        assert_eq!(info.file_name(), "test.txt");
    }

    #[test]
    fn from_name_empty_string() {
        let info = FileNameInformation::from_name(String::new());
        assert_eq!(info.file_name_length(), 0);
        assert_eq!(info.file_name(), "");
    }

    #[test]
    fn from_name_round_trip() {
        let info = FileNameInformation::from_name("hello.doc".into());
        let bytes = info.smb_to_bytes();
        let (_, parsed) = FileNameInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn from_name_length_matches_wire_size() {
        let info = FileNameInformation::from_name("testfile.txt".into());
        let bytes = info.smb_to_bytes();
        // Wire: 4 bytes (length field) + 24 bytes (12 UTF-16 code units)
        assert_eq!(bytes.len(), 4 + 24);
        // The length field in the first 4 bytes should equal 24
        let wire_length = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(wire_length, 24);
    }
}
