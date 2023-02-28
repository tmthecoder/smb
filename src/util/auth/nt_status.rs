#[repr(u32)]
pub enum NTStatus {
    StatusSuccess = 0x0,
    SecIContinueNeeded = 0x00090312,
    UnknownError = 0xFFFFFFFF,
}