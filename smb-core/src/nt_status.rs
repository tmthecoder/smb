#[repr(u32)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NTStatus {
    StatusSuccess = 0x0,
    SecIContinueNeeded = 0x00090312,
    InvalidParameter = 0xC000000D,
    AccessDenied = 0xC0000022,
    StatusLogonFailure = 0xC000006D,
    StatusNotSupported = 0xC00000BB,
    RequestNotAccepted = 0xC00000D0,
    UserSessionDeleted = 0xC0000203,
    NetworkSessionExpired = 0xC000035C,
    UnknownError = 0xFFFFFFFF,
}