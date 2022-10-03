use crate::header::Header;

mod body;
mod capabilities;
mod filetime;
mod negotiate;
mod negotiate_context;
mod security_mode;
mod session_setup;

pub type SMBBody = body::SMBBody;

pub type LegacySMBBody = body::LegacySMBBody;

pub type Capabilities = capabilities::Capabilities;
pub type FileTime = filetime::FileTime;
pub type SecurityMode = security_mode::SecurityMode;

pub type SMBDialect = negotiate::SMBDialect;
pub type SMBNegotiationRequest = negotiate::SMBNegotiationRequestBody;
pub type SMBNegotiationResponse = negotiate::SMBNegotiationResponseBody;
pub type SMBSessionSetupRequest = session_setup::SMBSessionSetupRequestBody;
pub type SMBSessionSetupResponse = session_setup::SMBSessionSetupResponseBody;
pub type NegotiateContext = negotiate_context::NegotiateContext;

pub trait Body<S: Header> {
    type Item;

    fn from_bytes_and_header_exists<'a>(bytes: &'a [u8], header: &S) -> Option<(Self::Item, &'a [u8])>;
    fn from_bytes_and_header<'a>(bytes: &'a [u8], header: &S) -> (Self::Item, &'a [u8]);
    fn as_bytes(&self) -> Vec<u8>;
}