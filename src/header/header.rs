use crate::header;
use crate::header::SMBCommandCode;

pub(crate) struct SMBHeader {
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



