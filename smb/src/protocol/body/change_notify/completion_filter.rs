use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

bitflags! {
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SMBCompletionFilter: u16 {
        const FILE_NAME = 0x01;
        const DIR_NAME = 0x02;
        const ATTRIBUTES = 0x04;
        const SIZE = 0x08;
        const LAST_WRITE_TIME = 0x10;
        const LAST_ACCESS_TIME = 0x20;
        const CREATION_TIME = 0x40;
        const EA = 0x80;
        const SECURITY = 0x100;
        const STREAM_NAME = 0x200;
        const STREAM_SIZE = 0x400;
        const STREAM_WRITE = 0x800;
    }
}

impl_smb_byte_size_for_bitflag!(SMBCompletionFilter);
impl_smb_to_bytes_for_bitflag!(SMBCompletionFilter);
impl_smb_from_bytes_for_bitflag!(SMBCompletionFilter);
