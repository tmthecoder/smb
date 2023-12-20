use smb_core::{SMBEnumFromBytes, SMBFromBytes, SMBParseResult, SMBToBytes};

use crate::protocol::header::Header;

mod body;
mod capabilities;
mod dialect;
mod filetime;
pub mod negotiate;
pub mod session_setup;

pub mod logoff;
pub mod tree_connect;
pub mod tree_disconnect;
pub mod empty;
pub mod create;

pub type SMBBody = body::SMBBody;

pub type LegacySMBBody = body::LegacySMBBody;

pub type Capabilities = capabilities::Capabilities;
pub type FileTime = filetime::FileTime;

pub type SMBDialect = dialect::SMBDialect;

pub trait Body<S: Header>: SMBEnumFromBytes + SMBToBytes {
    fn parse_with_cc(bytes: &[u8], command_code: S::CommandCode) -> SMBParseResult<&[u8], Self> where Self: Sized;
    fn as_bytes(&self) -> Vec<u8>;
}