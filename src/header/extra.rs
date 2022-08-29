use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBExtra {
    smth: u16,
    signature: u32
}

impl SMBExtra {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        SMBExtra {
            smth: 0,
            signature: 0,
        }
    }
}

impl SMBExtra {
    pub fn as_bytes(&self) -> Vec<u8> {
        [&self.smth.to_be_bytes()[0..], &self.signature.to_be_bytes()[0..]].concat()
    }
}