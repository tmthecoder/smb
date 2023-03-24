use crate::util::as_bytes::AsByteVec;
use crate::util::auth::nt_status::NTStatus;

pub mod ntlm;
pub mod spnego;
mod auth_context;
mod user;
pub mod nt_status;

pub type User = user::User;
pub type AuthContext = auth_context::AuthContext;

pub trait AuthProvider {
    type Message: AsByteVec;
    type Context;

    fn get_oid() -> Vec<u8>;

    fn accept_security_context(&self, input_token: &Self::Message, context: &mut Self::Context) -> (NTStatus, Self::Message);
}
