//! MS-FSCC File Information Classes
//!
//! Typed representations of the file information structures defined in
//! [MS-FSCC] sections 2.4.x, used in QueryInfo / SetInfo responses.

mod access;
mod alignment;
mod basic;
mod ea;
mod internal;
mod mode;
mod name;
mod network_open;
mod position;
mod standard;

pub use access::FileAccessInformation;
pub use alignment::FileAlignmentInformation;
pub use basic::FileBasicInformation;
pub use ea::FileEaInformation;
pub use internal::FileInternalInformation;
pub use mode::FileModeInformation;
pub use name::FileNameInformation;
pub use network_open::FileNetworkOpenInformation;
pub use position::FilePositionInformation;
pub use standard::FileStandardInformation;

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
    use crate::protocol::body::create::file_attributes::SMBFileAttributes;
    use crate::protocol::body::filetime::FileTime;

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
