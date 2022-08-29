use crate::header::{SMBCommandCode, SMBExtra, SMBFlags, SMBFlags2, SMBStatus};

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



