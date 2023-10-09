use smb_core::SMBParseResult;

use crate::protocol::header::Header;

mod body;
mod capabilities;
mod dialect;
mod filetime;
pub mod negotiate;
pub mod session_setup;

pub type SMBBody = body::SMBBody;

pub type LegacySMBBody = body::LegacySMBBody;

pub type Capabilities = capabilities::Capabilities;
pub type FileTime = filetime::FileTime;

pub type SMBDialect = dialect::SMBDialect;

pub trait Body<S: Header> {
    fn parse_with_cc(bytes: &[u8], command_code: S::CommandCode) -> SMBParseResult<&[u8], Self> where Self: Sized;
    fn as_bytes(&self) -> Vec<u8>;
}