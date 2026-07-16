use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::byte_helper::{bytes_to_u32, bytes_to_u64, u32_to_bytes, u64_to_bytes};

#[derive(
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Debug,
    Clone,
    SMBFromBytes,
    SMBToBytes,
    SMBByteSize,
    Default,
)]
pub struct FileTime {
    #[smb_direct(start(fixed = 0))]
    low_date_time: u32,
    #[smb_direct(start(fixed = 4))]
    high_date_time: u32,
}

/// Seconds between the FILETIME epoch (1601-01-01) and the Unix epoch (1970-01-01)
const SECS_BETWEEN_1601_AND_UNIX_EPOCH: u64 = 11_644_473_600;
/// FILETIME resolution: 100-nanosecond intervals per second (MS-DTYP §2.3.3)
const INTERVALS_PER_SEC: u64 = 10_000_000;

impl FileTime {
    pub fn from_unix(unix_timestamp: u64) -> Self {
        // MS-DTYP §2.3.3: FILETIME counts 100-nanosecond intervals since 1601-01-01
        let intervals =
            (unix_timestamp + SECS_BETWEEN_1601_AND_UNIX_EPOCH).saturating_mul(INTERVALS_PER_SEC);
        let bytes = u64_to_bytes(intervals);
        FileTime {
            low_date_time: bytes_to_u32(&bytes[0..4]),
            high_date_time: bytes_to_u32(&bytes[4..]),
        }
    }

    pub fn zero() -> Self {
        FileTime {
            low_date_time: 0,
            high_date_time: 0,
        }
    }

    pub fn now() -> Self {
        let time_now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        Self::from_unix(time_now.as_secs())
    }

    pub fn to_unix(&self) -> u64 {
        let bytes = self.as_bytes();
        (bytes_to_u64(&bytes) / INTERVALS_PER_SEC).saturating_sub(SECS_BETWEEN_1601_AND_UNIX_EPOCH)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let low_bytes = u32_to_bytes(self.low_date_time);
        let high_bytes = u32_to_bytes(self.high_date_time);
        [low_bytes, high_bytes].concat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_filetime() {
        let ft = FileTime::zero();
        let bytes = ft.as_bytes();
        assert_eq!(bytes, [0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn now_is_nonzero() {
        let ft = FileTime::now();
        let bytes = ft.as_bytes();
        assert_ne!(bytes, [0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn filetime_is_8_bytes() {
        let ft = FileTime::now();
        assert_eq!(ft.as_bytes().len(), 8);
    }

    #[test]
    fn unix_round_trip() {
        let unix_ts: u64 = 1700000000;
        let ft = FileTime::from_unix(unix_ts);
        let back = ft.to_unix();
        assert!(
            (back as i64 - unix_ts as i64).abs() < 2,
            "Unix timestamp should round-trip: got {} expected {}",
            back,
            unix_ts
        );
    }

    /// MS-DTYP §2.3.3: FILETIME is the count of 100-ns intervals since
    /// 1601-01-01. Verify against a known reference value:
    /// 2023-11-14T22:13:20Z (unix 1700000000) = 133444736000000000 intervals.
    #[test]
    fn from_unix_produces_correct_filetime_intervals() {
        let ft = FileTime::from_unix(1700000000);
        let raw = bytes_to_u64(&ft.as_bytes());
        assert_eq!(raw, 133_444_736_000_000_000);
    }

    #[test]
    fn unix_epoch_maps_to_1601_offset() {
        let ft = FileTime::from_unix(0);
        let raw = bytes_to_u64(&ft.as_bytes());
        assert_eq!(raw, 11_644_473_600 * 10_000_000);
    }
}
