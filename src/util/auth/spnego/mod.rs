mod spnego_token;
mod spnego_token_init;
mod spnego_token_init_2;
mod spnego_token_response;

pub(crate) mod util;

pub type SPNEGOToken<T> = spnego_token::SPNEGOToken<T>;
pub type SPNEGOTokenInitBody<T> = spnego_token_init::SPNEGOTokenInitBody<T>;
pub type SPNEGOTokenInit2Body<T> = spnego_token_init_2::SPNEGOTokenInit2Body<T>;
pub type SPNEGOTokenResponseBody<T> = spnego_token_response::SPNEGOTokenResponseBody<T>;