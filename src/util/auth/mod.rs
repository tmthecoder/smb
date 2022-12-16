pub mod ntlm;
pub mod spnego;
mod user;

pub type User = user::User;

pub trait AuthProvider {
    type Item;

    fn get_oid() -> Vec<u8>;

    fn accept_security_context(&self, input_token: &Self::Item, output_token: &mut Self::Item) -> u8;
}
