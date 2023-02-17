use nom::IResult;
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
    fn parse_with_cc(bytes: &[u8], command_code: S::CommandCode) -> IResult<&[u8], Self> where Self: Sized;
    fn as_bytes(&self) -> Vec<u8>;
}