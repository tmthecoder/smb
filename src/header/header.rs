use crate::header;

pub struct SMBHeader {
    command: SMBCommandCode,
    status: SMBStatus,
    flags: SMBFlags,
    flags2: SMBFlags2,
    extra: SMBExtra,
    tid: u16,
    pid: u16,
    uid: u16,
    mid: u16
}

enum SMBStatus {
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

enum SMBFlags {

}

enum SMBFlags2 {

}

enum SMBExtra {

}

