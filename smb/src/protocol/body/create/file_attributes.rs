use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

bitflags! {
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SMBFileAttributes: u32 {
        const READONLY = 0x00000001;
        const HIDDEN = 0x00000002;
        const SYSTEM = 0x00000004;
        const DIRECTORY = 0x00000010;
        const ARCHIVE = 0x00000020;
        const NORMAL = 0x00000080;
        const TEMPORARY = 0x00000100;
        const SPARSE_FILE = 0x00000200;
        const REPARSE_POINT= 0x00000400;
        const COMPRESSED = 0x00000800;
        const OFFLINE = 0x00001000;
        const NOT_CONTENT_INDEXED = 0x00002000;
        const ENCRYPTED = 0x00004000;
        const INTEGRITY_STREAM = 0x00008000;
        const NO_SCRUB_DATA = 0x00020000;
        const RECALL_ON_OPEN = 0x00040000;
        const PINNED = 0x00080000;
        const UNPINNED = 0x00100000;
        const RECALL_ON_DATA_ACCESS = 0x00400000;
    }
}

impl_smb_byte_size_for_bitflag! { SMBFileAttributes }
impl_smb_to_bytes_for_bitflag! { SMBFileAttributes }
impl_smb_from_bytes_for_bitflag! { SMBFileAttributes }
