mod header;
mod command_code;
mod status;
mod flags;
mod flags2;
mod extra;

pub type SMBCommandCode = command_code::SMBCommandCode;
pub type SMBHeader = header::SMBHeader;
pub type SMBStatus = status::SMBStatus;
pub type SMBFlags = flags::SMBFlags;
pub type SMBFlags2 = flags2::SMBFlags2;
pub type SMBExtra = extra::SMBExtra;