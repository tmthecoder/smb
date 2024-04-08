use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

bitflags! {
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SMBCreateOptions: u32 {
        const DIRECTORY_FILE            = 0x000001;
        const WRITE_THROUGH             = 0x000002;
        const SEQUENTIAL_ONLY           = 0x000004;
        const NO_INTERMEDIATE_BUFFERING = 0x000008;
        const SYNCHRONOUS_IO_ALERT      = 0x000010;
        const SYNCHRONOUS_IO_NONALERT   = 0x000020;
        const NON_DIRECTORY_FILE        = 0x000040;
        const COMPLETE_IF_OPLOCKED      = 0x000100;
        const NO_EA_KNOWLEDGE           = 0x000200;
        const RANDOM_ACCESS             = 0x000800;
        const DELETE_ON_CLOSE           = 0x001000;
        const OPEN_BY_FILE_ID           = 0x002000;
        const OPEN_FOR_BACKUP_INTENR    = 0x004000;
        const NO_COMPRESSION            = 0x008000;
        const OPEN_REMOTE_INSTANCE      = 0x000400; // Ignored
        const OPEN_REQUIRING_OPLOCK     = 0x010000; // Ignored
        const DISALLOW_EXCLUSIVE        = 0x020000; // Ignored
        const RESERVE_OPFILTER          = 0x100000; // Fails if set
        const OPEN_REPARSE_POINT        = 0x200000;
        const OPEN_NO_RECALL            = 0x400000;
        const OPEN_FOR_FREE_SPACE_QUERY = 0x800000;
    }
}

impl_smb_byte_size_for_bitflag! { SMBCreateOptions }
impl_smb_to_bytes_for_bitflag! { SMBCreateOptions }
impl_smb_from_bytes_for_bitflag! { SMBCreateOptions }