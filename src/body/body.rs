use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum SMBBody {
    None,
    Negotiate(Vec<String>)
}