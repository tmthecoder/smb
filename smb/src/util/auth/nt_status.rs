#[repr(u32)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NTStatus {
    StatusSuccess = 0x0,
    SecIContinueNeeded = 0x00090312,
    StatusLogonFailure = 0xC000006D,
    UnknownError = 0xFFFFFFFF,
}