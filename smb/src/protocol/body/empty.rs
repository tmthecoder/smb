use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

#[derive(
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Debug,
    SMBFromBytes,
    SMBToBytes,
    SMBByteSize,
    Clone
)]
#[smb_byte_tag(value = 4)]
#[smb_skip(start = 0, length = 4)]
pub struct SMBEmpty;