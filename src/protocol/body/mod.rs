use crate::protocol::header::Header;

mod body;
mod capabilities;
mod common_types;
mod filetime;
pub mod negotiate;
mod security_mode;
mod session_setup;

pub type SMBBody = body::SMBBody;

pub type LegacySMBBody = body::LegacySMBBody;

pub type Capabilities = capabilities::Capabilities;
pub type FileTime = filetime::FileTime;
pub type SecurityMode = security_mode::SecurityMode;

pub type SMBDialect = common_types::SMBDialect;
pub type SMBSessionSetupRequest = session_setup::SMBSessionSetupRequestBody;
pub type SMBSessionSetupResponse = session_setup::SMBSessionSetupResponseBody;

// Negotiate Ctx Specific


pub trait Body<S: Header> {
    fn from_bytes_and_header_exists<'a>(bytes: &'a [u8], header: &S) -> Option<(Self, &'a [u8])> where Self: Sized;
    fn from_bytes_and_header<'a>(bytes: &'a [u8], header: &S) -> (Self, &'a [u8]) where Self: Sized;
    fn as_bytes(&self) -> Vec<u8>;
}