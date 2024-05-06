use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::oplock_break::oplock_level::SMBOplockLevel;

mod oplock_level;

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize)]
#[smb_byte_tag(24)]
pub struct SMBOplockBreakContent {
    #[smb_direct(start(fixed = 2))]
    level: SMBOplockLevel,
    #[smb_skip(start = 3, length = 1)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_skip(start = 4, length = 4)]
    reserved2: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 8))]
    file_id: SMBFileId,
}

pub type SMBOplockBreakAcknowledgement = SMBOplockBreakContent;