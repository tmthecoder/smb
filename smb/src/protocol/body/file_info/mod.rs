//! MS-FSCC File Information Classes
//!
//! Typed representations of the file information structures defined in
//! [MS-FSCC] sections 2.4.x, used in QueryInfo / SetInfo responses.

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::file_attributes::SMBFileAttributes;
use crate::protocol::body::filetime::FileTime;

/// FILE_BASIC_INFORMATION (MS-FSCC 2.4.7) — 40 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileBasicInformation {
    #[smb_direct(start(fixed = 0))]
    pub creation_time: FileTime,
    #[smb_direct(start(fixed = 8))]
    pub last_access_time: FileTime,
    #[smb_direct(start(fixed = 16))]
    pub last_write_time: FileTime,
    #[smb_direct(start(fixed = 24))]
    pub change_time: FileTime,
    #[smb_direct(start(fixed = 32))]
    pub file_attributes: SMBFileAttributes,
    #[smb_direct(start(fixed = 36))]
    pub reserved: u32,
}

/// FILE_STANDARD_INFORMATION (MS-FSCC 2.4.41) — 24 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileStandardInformation {
    #[smb_direct(start(fixed = 0))]
    pub allocation_size: u64,
    #[smb_direct(start(fixed = 8))]
    pub end_of_file: u64,
    #[smb_direct(start(fixed = 16))]
    pub number_of_links: u32,
    #[smb_direct(start(fixed = 20))]
    pub delete_pending: u8,
    #[smb_direct(start(fixed = 21))]
    pub directory: u8,
    #[smb_direct(start(fixed = 22))]
    pub reserved: u16,
}

/// FILE_INTERNAL_INFORMATION (MS-FSCC 2.4.20) — 8 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileInternalInformation {
    #[smb_direct(start(fixed = 0))]
    pub index_number: u64,
}

/// FILE_EA_INFORMATION (MS-FSCC 2.4.12) — 4 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileEaInformation {
    #[smb_direct(start(fixed = 0))]
    pub ea_size: u32,
}

/// FILE_ACCESS_INFORMATION (MS-FSCC 2.4.1) — 4 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileAccessInformation {
    #[smb_direct(start(fixed = 0))]
    pub access_flags: u32,
}

/// FILE_POSITION_INFORMATION (MS-FSCC 2.4.35) — 8 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FilePositionInformation {
    #[smb_direct(start(fixed = 0))]
    pub current_byte_offset: u64,
}

/// FILE_MODE_INFORMATION (MS-FSCC 2.4.26) — 4 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileModeInformation {
    #[smb_direct(start(fixed = 0))]
    pub mode: u32,
}

/// FILE_ALIGNMENT_INFORMATION (MS-FSCC 2.4.3) — 4 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileAlignmentInformation {
    #[smb_direct(start(fixed = 0))]
    pub alignment_requirement: u32,
}

/// FILE_NAME_INFORMATION (MS-FSCC 2.4.28) — variable length
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileNameInformation {
    #[smb_direct(start(fixed = 0))]
    pub file_name_length: u32,
    #[smb_string(order = 0, start(fixed = 4), length(inner(start = 0, num_type = "u32")), underlying = "u16")]
    pub file_name: String,
}

/// FILE_NETWORK_OPEN_INFORMATION (MS-FSCC 2.4.29) — 56 bytes
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileNetworkOpenInformation {
    #[smb_direct(start(fixed = 0))]
    pub creation_time: FileTime,
    #[smb_direct(start(fixed = 8))]
    pub last_access_time: FileTime,
    #[smb_direct(start(fixed = 16))]
    pub last_write_time: FileTime,
    #[smb_direct(start(fixed = 24))]
    pub change_time: FileTime,
    #[smb_direct(start(fixed = 32))]
    pub allocation_size: u64,
    #[smb_direct(start(fixed = 40))]
    pub end_of_file: u64,
    #[smb_direct(start(fixed = 48))]
    pub file_attributes: SMBFileAttributes,
    #[smb_direct(start(fixed = 52))]
    pub reserved: u32,
}

/// FILE_ALL_INFORMATION (MS-FSCC 2.4.2) — composite structure
///
/// This is a concatenation of the sub-structures above.
/// We serialize it by concatenating each sub-struct's bytes rather than
/// using the derive macro, because the derive macro doesn't support
/// nested struct composition at variable offsets.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FileAllInformation {
    pub basic: FileBasicInformation,
    pub standard: FileStandardInformation,
    pub internal: FileInternalInformation,
    pub ea: FileEaInformation,
    pub access: FileAccessInformation,
    pub position: FilePositionInformation,
    pub mode: FileModeInformation,
    pub alignment: FileAlignmentInformation,
    pub name: FileNameInformation,
}

impl FileAllInformation {
    pub fn to_bytes(&self) -> Vec<u8> {
        use smb_core::SMBToBytes;
        let mut buf = Vec::with_capacity(104);
        buf.extend_from_slice(&self.basic.smb_to_bytes());
        buf.extend_from_slice(&self.standard.smb_to_bytes());
        buf.extend_from_slice(&self.internal.smb_to_bytes());
        buf.extend_from_slice(&self.ea.smb_to_bytes());
        buf.extend_from_slice(&self.access.smb_to_bytes());
        buf.extend_from_slice(&self.position.smb_to_bytes());
        buf.extend_from_slice(&self.mode.smb_to_bytes());
        buf.extend_from_slice(&self.alignment.smb_to_bytes());
        buf.extend_from_slice(&self.name.smb_to_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBByteSize, SMBFromBytes, SMBToBytes};

    #[test]
    fn file_basic_information_size_is_40() {
        let info = FileBasicInformation {
            creation_time: FileTime::zero(),
            last_access_time: FileTime::zero(),
            last_write_time: FileTime::zero(),
            change_time: FileTime::zero(),
            file_attributes: SMBFileAttributes::NORMAL,
            reserved: 0,
        };
        assert_eq!(info.smb_byte_size(), 40);
    }

    #[test]
    fn file_basic_information_round_trip() {
        let info = FileBasicInformation {
            creation_time: FileTime::now(),
            last_access_time: FileTime::now(),
            last_write_time: FileTime::now(),
            change_time: FileTime::now(),
            file_attributes: SMBFileAttributes::ARCHIVE | SMBFileAttributes::READONLY,
            reserved: 0,
        };
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 40);
        let (_, parsed) = FileBasicInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn file_standard_information_size_is_24() {
        let info = FileStandardInformation {
            allocation_size: 4096,
            end_of_file: 1024,
            number_of_links: 1,
            delete_pending: 0,
            directory: 0,
            reserved: 0,
        };
        assert_eq!(info.smb_byte_size(), 24);
    }

    #[test]
    fn file_standard_information_round_trip() {
        let info = FileStandardInformation {
            allocation_size: 8192,
            end_of_file: 2048,
            number_of_links: 3,
            delete_pending: 1,
            directory: 0,
            reserved: 0,
        };
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 24);
        let (_, parsed) = FileStandardInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn file_internal_information_round_trip() {
        let info = FileInternalInformation { index_number: 42 };
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 8);
        let (_, parsed) = FileInternalInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn file_ea_information_round_trip() {
        let info = FileEaInformation { ea_size: 0 };
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 4);
        let (_, parsed) = FileEaInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn file_access_information_round_trip() {
        let info = FileAccessInformation { access_flags: 0x001f01ff };
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 4);
        let (_, parsed) = FileAccessInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn file_position_information_round_trip() {
        let info = FilePositionInformation { current_byte_offset: 512 };
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 8);
        let (_, parsed) = FilePositionInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn file_mode_information_round_trip() {
        let info = FileModeInformation { mode: 0 };
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 4);
        let (_, parsed) = FileModeInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn file_alignment_information_round_trip() {
        let info = FileAlignmentInformation { alignment_requirement: 0 };
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 4);
        let (_, parsed) = FileAlignmentInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn file_network_open_information_size_is_56() {
        let info = FileNetworkOpenInformation {
            creation_time: FileTime::zero(),
            last_access_time: FileTime::zero(),
            last_write_time: FileTime::zero(),
            change_time: FileTime::zero(),
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: SMBFileAttributes::NORMAL,
            reserved: 0,
        };
        assert_eq!(info.smb_byte_size(), 56);
    }

    #[test]
    fn file_network_open_information_round_trip() {
        let info = FileNetworkOpenInformation {
            creation_time: FileTime::now(),
            last_access_time: FileTime::now(),
            last_write_time: FileTime::now(),
            change_time: FileTime::now(),
            allocation_size: 4096,
            end_of_file: 1024,
            file_attributes: SMBFileAttributes::ARCHIVE,
            reserved: 0,
        };
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 56);
        let (_, parsed) = FileNetworkOpenInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn file_all_information_contains_all_sub_structs() {
        let all = FileAllInformation {
            basic: FileBasicInformation {
                creation_time: FileTime::zero(),
                last_access_time: FileTime::zero(),
                last_write_time: FileTime::zero(),
                change_time: FileTime::zero(),
                file_attributes: SMBFileAttributes::NORMAL,
                reserved: 0,
            },
            standard: FileStandardInformation {
                allocation_size: 4096,
                end_of_file: 21,
                number_of_links: 1,
                delete_pending: 0,
                directory: 0,
                reserved: 0,
            },
            internal: FileInternalInformation { index_number: 0 },
            ea: FileEaInformation { ea_size: 0 },
            access: FileAccessInformation { access_flags: 0x001f01ff },
            position: FilePositionInformation { current_byte_offset: 0 },
            mode: FileModeInformation { mode: 0 },
            alignment: FileAlignmentInformation { alignment_requirement: 0 },
            name: FileNameInformation {
                file_name_length: 24,
                file_name: "testfile.txt".into(),
            },
        };
        let bytes = all.to_bytes();
        // 40 + 24 + 8 + 4 + 4 + 8 + 4 + 4 + (4 + 24) = 124
        assert_eq!(bytes.len(), 124);
    }

    #[test]
    fn file_all_information_basic_segment_matches_standalone() {
        let basic = FileBasicInformation {
            creation_time: FileTime::now(),
            last_access_time: FileTime::now(),
            last_write_time: FileTime::now(),
            change_time: FileTime::now(),
            file_attributes: SMBFileAttributes::ARCHIVE,
            reserved: 0,
        };
        let all = FileAllInformation {
            basic: basic.clone(),
            standard: FileStandardInformation {
                allocation_size: 0, end_of_file: 0, number_of_links: 1,
                delete_pending: 0, directory: 0, reserved: 0,
            },
            internal: FileInternalInformation { index_number: 0 },
            ea: FileEaInformation { ea_size: 0 },
            access: FileAccessInformation { access_flags: 0 },
            position: FilePositionInformation { current_byte_offset: 0 },
            mode: FileModeInformation { mode: 0 },
            alignment: FileAlignmentInformation { alignment_requirement: 0 },
            name: FileNameInformation { file_name_length: 0, file_name: String::new() },
        };
        let all_bytes = all.to_bytes();
        let basic_bytes = basic.smb_to_bytes();
        assert_eq!(&all_bytes[..40], &basic_bytes[..]);
    }
}
