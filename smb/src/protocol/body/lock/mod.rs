use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::empty::SMBEmpty;
use crate::protocol::body::lock::info::SMBLockInfo;

mod info;
mod flags;

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize)]
#[smb_byte_tag(48)]
pub struct SMBLockRequest {
    #[smb_direct(start(fixed = 4))]
    lock_seqno_idx: u32,
    #[smb_direct(start(fixed = 8))]
    file_id: SMBFileId,
    #[smb_vector(count(inner(start = 2, num_type = "u16")), order = 0)]
    locks: Vec<SMBLockInfo>,
}

pub type SMBLockResponse = SMBEmpty;