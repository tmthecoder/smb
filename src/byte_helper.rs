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