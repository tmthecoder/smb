pub(crate) fn bytes_to_u16(bytes: &[u8]) -> u16 {
    (bytes[0] as u16) | ((bytes[1] as u16) << 8)
}

pub(crate) fn u16_to_bytes(num: u16) -> [u8; 2] {
    [(num & 0xFF) as u8, ((num >> 8) & 0xFF) as u8]
}

pub(crate) fn bytes_to_u32(bytes: &[u8]) -> u32 {
    (bytes[0] as u32) |
    ((bytes[1] as u32) << 8) |
    ((bytes[2] as u32) << 16) |
    ((bytes[3] as u32) << 24)
}

pub(crate) fn u32_to_bytes(num: u32) -> [u8; 4] {
    [
        (num & 0xFF) as u8,
        ((num >> 8) & 0xFF) as u8,
        ((num >> 16) & 0xFF) as u8,
        ((num >> 24) & 0xFF) as u8,
    ]
}

pub(crate) fn bytes_to_u64(bytes: &[u8]) -> u64 {
    (bytes[0] as u64) |
    ((bytes[1] as u64) << 8) |
    ((bytes[2] as u64) << 16) |
    ((bytes[3] as u64) << 24) |
    ((bytes[4] as u64) << 32) |
    ((bytes[5] as u64) << 40) |
    ((bytes[6] as u64) << 48) |
    ((bytes[7] as u64) << 54)
}

pub(crate) fn u64_to_bytes(num: u64) -> [u8; 8] {
    [
        (num & 0xFF) as u8,
        ((num >> 8) & 0xFF) as u8,
        ((num >> 16) & 0xFF) as u8,
        ((num >> 24) & 0xFF) as u8,
        ((num >> 32) & 0xFF) as u8,
        ((num >> 40) & 0xFF) as u8,
        ((num >> 48) & 0xFF) as u8,
        ((num >> 54) & 0xFF) as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u16_round_trip() {
        let val: u16 = 0x0210;
        let bytes = u16_to_bytes(val);
        assert_eq!(bytes, [0x10, 0x02]);
        assert_eq!(bytes_to_u16(&bytes), val);
    }

    #[test]
    fn u32_round_trip() {
        let val: u32 = 0x00000001;
        let bytes = u32_to_bytes(val);
        assert_eq!(bytes, [0x01, 0x00, 0x00, 0x00]);
        assert_eq!(bytes_to_u32(&bytes), val);
    }

    #[test]
    fn u64_round_trip() {
        let val: u64 = 0x0000_0000_0000_0001;
        let bytes = u64_to_bytes(val);
        assert_eq!(bytes, [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(bytes_to_u64(&bytes), val);
    }

    /// NOTE: byte_helper.rs has a bug — bit shift 54 instead of 56 for the
    /// high byte in both bytes_to_u64 and u64_to_bytes. This test will fail
    /// until that is fixed.
    #[test]
    fn u64_max_value_round_trip() {
        let val: u64 = u64::MAX;
        let bytes = u64_to_bytes(val);
        assert_eq!(bytes_to_u64(&bytes), val, "u64::MAX should round-trip correctly");
    }

    #[test]
    fn u64_high_bits_correctness() {
        let val: u64 = 0xFF00_0000_0000_0000;
        let bytes = u64_to_bytes(val);
        assert_eq!(bytes[7], 0xFF, "High byte should be 0xFF");
        assert_eq!(bytes_to_u64(&bytes), val, "High-byte-only u64 should round-trip");
    }
}