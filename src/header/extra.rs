use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBExtra {
    smth: u16,
    signature: u32
}

impl SMBExtra {
    pub fn from_slice(bytes: &[u8]) -> Self {
        SMBExtra {
            smth: 0,
            signature: 0,
        }
    }
}