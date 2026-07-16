use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::file_attributes::SMBFileAttributes;
use crate::protocol::body::filetime::FileTime;

use super::DirectoryInformationEntry;

/// FILE_ID_BOTH_DIR_INFORMATION (MS-FSCC 2.4.17) — 104-byte fixed part
/// followed by a variable-length UTF-16 file name.
///
/// Returned for QueryDirectory requests with information class
/// FileIdBothDirectoryInformation (0x25). Entries are chained via
/// `next_entry_offset` with 8-byte alignment between entries.
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes,
)]
pub struct FileIdBothDirectoryInformation {
    #[smb_direct(start(fixed = 0))]
    next_entry_offset: u32,
    #[smb_direct(start(fixed = 4))]
    file_index: u32,
    #[smb_direct(start(fixed = 8))]
    creation_time: FileTime,
    #[smb_direct(start(fixed = 16))]
    last_access_time: FileTime,
    #[smb_direct(start(fixed = 24))]
    last_write_time: FileTime,
    #[smb_direct(start(fixed = 32))]
    change_time: FileTime,
    #[smb_direct(start(fixed = 40))]
    end_of_file: u64,
    #[smb_direct(start(fixed = 48))]
    allocation_size: u64,
    #[smb_direct(start(fixed = 56))]
    file_attributes: SMBFileAttributes,
    #[smb_direct(start(fixed = 60))]
    file_name_length: u32,
    #[smb_direct(start(fixed = 64))]
    ea_size: u32,
    #[smb_direct(start(fixed = 68))]
    short_name_length: u8,
    #[smb_skip(start = 69, length = 1)]
    reserved1: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 70))]
    short_name: [u8; 24],
    #[smb_skip(start = 94, length = 2)]
    reserved2: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 96))]
    file_id: u64,
    #[smb_string(
        order = 0,
        start(fixed = 104),
        length(inner(start = 60, num_type = "u32")),
        underlying = "u16"
    )]
    file_name: String,
}

impl FileIdBothDirectoryInformation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        change_time: FileTime,
        end_of_file: u64,
        allocation_size: u64,
        file_attributes: SMBFileAttributes,
        file_id: u64,
        file_name: String,
    ) -> Self {
        let file_name_length = (file_name.encode_utf16().count() * 2) as u32;
        Self {
            next_entry_offset: 0,
            file_index: 0,
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
            end_of_file,
            allocation_size,
            file_attributes,
            file_name_length,
            ea_size: 0,
            short_name_length: 0,
            reserved1: PhantomData,
            short_name: [0; 24],
            reserved2: PhantomData,
            file_id,
            file_name,
        }
    }

    pub fn next_entry_offset(&self) -> u32 {
        self.next_entry_offset
    }
    pub fn end_of_file(&self) -> u64 {
        self.end_of_file
    }
    pub fn allocation_size(&self) -> u64 {
        self.allocation_size
    }
    pub fn file_attributes(&self) -> SMBFileAttributes {
        self.file_attributes
    }
    pub fn file_id(&self) -> u64 {
        self.file_id
    }
    pub fn file_name(&self) -> &str {
        &self.file_name
    }
}

impl DirectoryInformationEntry for FileIdBothDirectoryInformation {
    fn set_next_entry_offset(&mut self, offset: u32) {
        self.next_entry_offset = offset;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBByteSize, SMBFromBytes, SMBToBytes};

    fn sample(name: &str) -> FileIdBothDirectoryInformation {
        FileIdBothDirectoryInformation::new(
            FileTime::from_unix(1700000000),
            FileTime::from_unix(1700000100),
            FileTime::from_unix(1700000200),
            FileTime::from_unix(1700000300),
            1024,
            4096,
            SMBFileAttributes::ARCHIVE,
            42,
            name.into(),
        )
    }

    /// MS-FSCC 2.4.17: the fixed portion is 104 bytes; the name follows.
    #[test]
    fn fixed_part_is_104_bytes() {
        let entry = sample("");
        assert_eq!(entry.smb_byte_size(), 104);
        let entry = sample("test.txt");
        // "test.txt" = 8 UTF-16 code units × 2 bytes
        assert_eq!(entry.smb_byte_size(), 104 + 16);
    }

    #[test]
    fn wire_layout_matches_ms_fscc() {
        let entry = sample("a");
        let bytes = entry.smb_to_bytes();
        assert_eq!(bytes.len(), 106);
        // EndOfFile at offset 40, AllocationSize at 48
        assert_eq!(u64::from_le_bytes(bytes[40..48].try_into().unwrap()), 1024);
        assert_eq!(u64::from_le_bytes(bytes[48..56].try_into().unwrap()), 4096);
        // FileAttributes (ARCHIVE = 0x20) at offset 56
        assert_eq!(u32::from_le_bytes(bytes[56..60].try_into().unwrap()), 0x20);
        // FileNameLength at offset 60 = 2 (one UTF-16 code unit)
        assert_eq!(u32::from_le_bytes(bytes[60..64].try_into().unwrap()), 2);
        // FileId at offset 96
        assert_eq!(u64::from_le_bytes(bytes[96..104].try_into().unwrap()), 42);
        // FileName ("a" UTF-16LE) at offset 104
        assert_eq!(&bytes[104..106], &[0x61, 0x00]);
    }

    #[test]
    fn round_trip() {
        let entry = sample("subdir_file.bin");
        let bytes = entry.smb_to_bytes();
        let (_, parsed) = FileIdBothDirectoryInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(entry, parsed);
    }

    #[test]
    fn set_next_entry_offset_is_serialized_at_offset_zero() {
        let mut entry = sample("x");
        entry.set_next_entry_offset(112);
        let bytes = entry.smb_to_bytes();
        assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 112);
    }
}
