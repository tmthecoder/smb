pub mod ntlm;
mod user;

pub type User = user::User;

pub trait AuthProvider<T> {
    fn accept_security_context(&self, input_token: &T, output_token: &mut T) -> u8;
}
