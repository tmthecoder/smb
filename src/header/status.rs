pub(crate) enum SMBStatus {
    NTStatus(NTStatusLevel),
    DosError(char, char, u16)
}

struct NTStatusCode {
    level: NTStatusLevel,
}

#[repr(u8)]
enum NTStatusLevel {
    Success,
    Information,
    Warning,
    Error
}