use nom::IResult;

mod header;
mod command_code;
mod status;
mod flags;
mod flags2;
mod extra;

pub type SMBCommandCode = command_code::SMBCommandCode;
pub type SMBSyncHeader = header::SMBSyncHeader;
pub type SMBFlags = flags::SMBFlags;
pub type SMBStatus = status::SMBStatus;
pub type SMBExtra = extra::SMBExtra;

pub type LegacySMBCommandCode = command_code::LegacySMBCommandCode;
pub type LegacySMBHeader = header::LegacySMBHeader;
pub type LegacySMBFlags = flags::LegacySMBFlags;
pub type LegacySMBFlags2 = flags2::LegacySMBFlags2;

pub trait Header {
    fn from_bytes(bytes: &[u8]) -> Option<(Self, &[u8])> where Self:Sized;
    fn parse(bytes: &[u8]) -> IResult<&[u8], Self> where Self:Sized;
    fn as_bytes(&self) -> Vec<u8>;
}