use crate::util::auth::AuthProvider;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct SPNEGOTokenInit2Body<T: AuthProvider> {
    mechanism: Option<T>
}

impl<T: AuthProvider> SPNEGOTokenInit2Body<T> {
    pub(crate) fn as_bytes(&self) -> Vec<u8> {Vec::new()}
}
