pub use auth_context::*;
use smb_core::nt_status::NTStatus;
use smb_core::SMBParseResult;
pub use user::*;

pub mod ntlm;
pub mod spnego;
mod auth_context;
mod user;
pub trait AuthProvider: Send + Sync {
    type Message: AuthMessage + Send + Sync + 'static;
    type Context: AuthContext + Send + Sync + 'static;

    fn get_oid() -> Vec<u8>;

    fn accept_security_context(&self, input_token: &Self::Message, context: &mut Self::Context) -> (NTStatus, Self::Message);
}

pub trait AuthMessage {
    fn parse(data: &[u8]) -> SMBParseResult<&[u8], Self> where Self: Sized;

    fn as_bytes(&self) -> Vec<u8>;

    fn empty() -> Self;
}

pub trait AuthContext {
    fn init() -> Self;
}

