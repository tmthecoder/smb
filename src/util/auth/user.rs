use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct User {
    pub username: String,
    pub password: String,
}

impl User {
    pub fn new(username: String, password: String) -> Self {
        Self { username, password }
    }
}