use serde::{Serialize, Deserialize};
use crate::byte_helper::{bytes_to_u16, bytes_to_u64, u16_to_bytes, u64_to_bytes};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBExtra {
    pid_high: u16,
    signature: u64
}

impl SMBExtra {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        SMBExtra {
            pid_high: bytes_to_u16(&bytes[0..2]),
            signature: bytes_to_u64(&bytes[2..10])
        }
    }
}

impl SMBExtra {
    pub fn as_bytes(&self) -> Vec<u8> {
        [
            &u16_to_bytes(self.pid_high)[0..],
            &u64_to_bytes(self.signature)[0..]
        ].concat()
    }
}