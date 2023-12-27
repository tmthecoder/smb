use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct User {
    pub username: String,
    pub password: String,
}

impl User {
    pub fn new<U: Into<String>, P: Into<String>>(username: U, password: P) -> Self {
        Self { username: username.into(), password: password.into() }
    }
}