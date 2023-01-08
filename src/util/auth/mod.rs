pub mod ntlm;
pub mod spnego;
mod auth_context;
mod user;

pub type User = user::User;
pub type AuthContext = auth_context::AuthContext;
pub trait AuthProvider {
    type Item;

    fn get_oid() -> Vec<u8>;

    fn accept_security_context(&self, input_token: &Self::Item) -> (u8, Self::Item);
}
