pub enum SMBStatus {
    NTStatus(NTStatusLevel),
    DosError(char, char, u16)
}

pub struct NTStatusCode {
    level: NTStatusLevel,
}

#[repr(u8)]
pub enum NTStatusLevel {
    Success,
    Information,
    Warning,
    Error
}