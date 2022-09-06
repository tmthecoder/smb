use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use crate::byte_helper::{bytes_to_u32, bytes_to_u64, u32_to_bytes, u64_to_bytes};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct FileTime {
    low_date_time: u32,
    high_date_time: u32,
}

const TIME_SINCE_1601_AND_EPOCH: u64 = 11644473600000;

impl FileTime {
    pub fn from_unix(unix_timestamp: u64) -> Self {
        let filetype_normalized = unix_timestamp + TIME_SINCE_1601_AND_EPOCH as u64;
        let bytes = u64_to_bytes(filetype_normalized);
        FileTime {
            low_date_time: bytes_to_u32(&bytes[0..4]),
            high_date_time: bytes_to_u32(&bytes[4..])
        }
    }

    pub fn now() -> Self {
        let time_now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        Self::from_unix(time_now.as_secs())
    }

    pub fn to_unix(&self) -> u64 {
        let low_bytes = u32_to_bytes(self.low_date_time);
        let high_bytes = u32_to_bytes(self.high_date_time);
        let merged = [low_bytes, high_bytes].concat();
        bytes_to_u64(&*merged)
    }
}