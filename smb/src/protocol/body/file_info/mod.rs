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

pub use access::{FileAccessInformation, FileAccessFlags};
pub use alignment::{FileAlignmentInformation, FileAlignmentRequirement};
pub use basic::FileBasicInformation;
pub use ea::FileEaInformation;
pub use internal::FileInternalInformation;
pub use mode::{FileModeInformation, FileModeFlags};
pub use name::FileNameInformation;
pub use network_open::FileNetworkOpenInformation;
pub use position::FilePositionInformation;
pub use standard::FileStandardInformation;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

/// FILE_ALL_INFORMATION (MS-FSCC 2.4.2) — composite structure
///
/// Concatenation of sub-structures at fixed offsets:
/// basic(40) + standard(24) + internal(8) + ea(4) + access(4)
/// + position(8) + mode(4) + alignment(4) + name(variable).
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, SMBByteSize, SMBFromBytes, SMBToBytes)]
pub struct FileAllInformation {
    #[smb_direct(start(fixed = 0))]
    basic: FileBasicInformation,
    #[smb_direct(start(fixed = 40))]
    standard: FileStandardInformation,
    #[smb_direct(start(fixed = 64))]
    internal: FileInternalInformation,
    #[smb_direct(start(fixed = 72))]
    ea: FileEaInformation,
    #[smb_direct(start(fixed = 76))]
    access: FileAccessInformation,
    #[smb_direct(start(fixed = 80))]
    position: FilePositionInformation,
    #[smb_direct(start(fixed = 88))]
    mode: FileModeInformation,
    #[smb_direct(start(fixed = 92))]
    alignment: FileAlignmentInformation,
    #[smb_direct(start(fixed = 96))]
    name: FileNameInformation,
}

impl FileAllInformation {
    pub fn new(
        basic: FileBasicInformation,
        standard: FileStandardInformation,
        internal: FileInternalInformation,
        ea: FileEaInformation,
        access: FileAccessInformation,
        position: FilePositionInformation,
        mode: FileModeInformation,
        alignment: FileAlignmentInformation,
        name: FileNameInformation,
    ) -> Self {
        Self { basic, standard, internal, ea, access, position, mode, alignment, name }
    }

    pub fn basic(&self) -> &FileBasicInformation { &self.basic }
    pub fn standard(&self) -> &FileStandardInformation { &self.standard }
    pub fn internal(&self) -> &FileInternalInformation { &self.internal }
    pub fn ea(&self) -> &FileEaInformation { &self.ea }
    pub fn access(&self) -> &FileAccessInformation { &self.access }
    pub fn position(&self) -> &FilePositionInformation { &self.position }
    pub fn mode(&self) -> &FileModeInformation { &self.mode }
    pub fn alignment(&self) -> &FileAlignmentInformation { &self.alignment }
    pub fn name(&self) -> &FileNameInformation { &self.name }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBByteSize, SMBFromBytes, SMBToBytes};
    use crate::protocol::body::create::file_attributes::SMBFileAttributes;
    use crate::protocol::body::filetime::FileTime;

    #[test]
    fn file_basic_information_size_is_40() {
        let info = FileBasicInformation::new(
            FileTime::zero(), FileTime::zero(), FileTime::zero(), FileTime::zero(),
            SMBFileAttributes::NORMAL,
        );
        assert_eq!(info.smb_byte_size(), 40);
    }

    #[test]
    fn file_basic_information_round_trip() {
        let info = FileBasicInformation::new(
            FileTime::now(), FileTime::now(), FileTime::now(), FileTime::now(),
            SMBFileAttributes::ARCHIVE | SMBFileAttributes::READONLY,
        );
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 40);
        let (_, parsed) = FileBasicInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn file_standard_information_size_is_24() {
        let info = FileStandardInformation::new(4096, 1024, 1, false, false);
        assert_eq!(info.smb_byte_size(), 24);
    }

    #[test]
    fn file_standard_information_round_trip() {
        let info = FileStandardInformation::new(8192, 2048, 3, true, false);
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 24);
        let (_, parsed) = FileStandardInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn file_standard_information_bool_getters() {
        let info = FileStandardInformation::new(0, 0, 1, true, false);
        assert!(info.delete_pending());
        assert!(!info.directory());

        let info2 = FileStandardInformation::new(0, 0, 1, false, true);
        assert!(!info2.delete_pending());
        assert!(info2.directory());
    }

    #[test]
    fn file_internal_information_round_trip() {
        let info = FileInternalInformation::new(42);
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 8);
        let (_, parsed) = FileInternalInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn file_ea_information_round_trip() {
        let info = FileEaInformation::new(0);
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 4);
        let (_, parsed) = FileEaInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn file_access_information_round_trip() {
        let info = FileAccessInformation::new(FileAccessFlags::from_bits_truncate(0x001f01ff));
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 4);
        let (_, parsed) = FileAccessInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn file_position_information_round_trip() {
        let info = FilePositionInformation::new(512);
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 8);
        let (_, parsed) = FilePositionInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn file_mode_information_round_trip() {
        let info = FileModeInformation::new(FileModeFlags::empty());
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 4);
        let (_, parsed) = FileModeInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn file_alignment_information_round_trip() {
        let info = FileAlignmentInformation::new(FileAlignmentRequirement::Byte);
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 4);
        let (_, parsed) = FileAlignmentInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn file_network_open_information_size_is_56() {
        let info = FileNetworkOpenInformation::new(
            FileTime::zero(), FileTime::zero(), FileTime::zero(), FileTime::zero(),
            0, 0, SMBFileAttributes::NORMAL,
        );
        assert_eq!(info.smb_byte_size(), 56);
    }

    #[test]
    fn file_network_open_information_round_trip() {
        let info = FileNetworkOpenInformation::new(
            FileTime::now(), FileTime::now(), FileTime::now(), FileTime::now(),
            4096, 1024, SMBFileAttributes::ARCHIVE,
        );
        let bytes = info.smb_to_bytes();
        assert_eq!(bytes.len(), 56);
        let (_, parsed) = FileNetworkOpenInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn file_all_information_contains_all_sub_structs() {
        let all = FileAllInformation::new(
            FileBasicInformation::new(
                FileTime::zero(), FileTime::zero(), FileTime::zero(), FileTime::zero(),
                SMBFileAttributes::NORMAL,
            ),
            FileStandardInformation::new(4096, 21, 1, false, false),
            FileInternalInformation::new(0),
            FileEaInformation::new(0),
            FileAccessInformation::new(FileAccessFlags::from_bits_truncate(0x001f01ff)),
            FilePositionInformation::new(0),
            FileModeInformation::new(FileModeFlags::empty()),
            FileAlignmentInformation::new(FileAlignmentRequirement::Byte),
            FileNameInformation::new(24, "testfile.txt".into()),
        );
        let bytes = all.smb_to_bytes();
        // 40 + 24 + 8 + 4 + 4 + 8 + 4 + 4 + (4 + 24) = 124
        assert_eq!(bytes.len(), 124);
    }

    #[test]
    fn file_all_information_basic_segment_matches_standalone() {
        let basic = FileBasicInformation::new(
            FileTime::now(), FileTime::now(), FileTime::now(), FileTime::now(),
            SMBFileAttributes::ARCHIVE,
        );
        let all = FileAllInformation::new(
            basic.clone(),
            FileStandardInformation::new(0, 0, 1, false, false),
            FileInternalInformation::new(0),
            FileEaInformation::new(0),
            FileAccessInformation::new(FileAccessFlags::empty()),
            FilePositionInformation::new(0),
            FileModeInformation::new(FileModeFlags::empty()),
            FileAlignmentInformation::new(FileAlignmentRequirement::Byte),
            FileNameInformation::new(0, String::new()),
        );
        let all_bytes = all.smb_to_bytes();
        let basic_bytes = basic.smb_to_bytes();
        assert_eq!(&all_bytes[..40], &basic_bytes[..]);
    }

    #[test]
    fn file_all_information_round_trip() {
        let all = FileAllInformation::new(
            FileBasicInformation::new(
                FileTime::now(), FileTime::now(), FileTime::now(), FileTime::now(),
                SMBFileAttributes::ARCHIVE,
            ),
            FileStandardInformation::new(4096, 512, 1, false, false),
            FileInternalInformation::new(7),
            FileEaInformation::new(0),
            FileAccessInformation::new(FileAccessFlags::from_bits_truncate(0x001f01ff)),
            FilePositionInformation::new(256),
            FileModeInformation::new(FileModeFlags::empty()),
            FileAlignmentInformation::new(FileAlignmentRequirement::Byte),
            FileNameInformation::new(24, "testfile.txt".into()),
        );
        let bytes = all.smb_to_bytes();
        let (_, parsed) = FileAllInformation::smb_from_bytes(&bytes).unwrap();
        assert_eq!(all, parsed);
    }

    #[test]
    fn file_all_information_getters() {
        let all = FileAllInformation::new(
            FileBasicInformation::new(
                FileTime::zero(), FileTime::zero(), FileTime::zero(), FileTime::zero(),
                SMBFileAttributes::NORMAL,
            ),
            FileStandardInformation::new(4096, 100, 1, false, false),
            FileInternalInformation::new(5),
            FileEaInformation::new(0),
            FileAccessInformation::new(FileAccessFlags::from_bits_truncate(0x001f01ff)),
            FilePositionInformation::new(50),
            FileModeInformation::new(FileModeFlags::empty()),
            FileAlignmentInformation::new(FileAlignmentRequirement::Byte),
            FileNameInformation::new(8, "test".into()),
        );
        assert_eq!(all.basic().file_attributes(), SMBFileAttributes::NORMAL);
        assert_eq!(all.standard().allocation_size(), 4096);
        assert_eq!(all.standard().end_of_file(), 100);
        assert_eq!(all.internal().index_number(), 5);
        assert_eq!(all.position().current_byte_offset(), 50);
        assert_eq!(all.name().file_name(), "test");
    }
}
