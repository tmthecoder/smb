use nom::error::ErrorKind;
use nom::IResult;

use smb_core::{SMBFromBytes, SMBToBytes};

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

pub enum SMBSender {
    Client,
    Server,
}

pub trait Header: SMBFromBytes + SMBToBytes {
    type CommandCode: Into<u64>;

    fn command_code(&self) -> Self::CommandCode;

    fn parse(bytes: &[u8]) -> IResult<&[u8], (Self, Self::CommandCode)> where Self: Sized + SMBFromBytes {
        let (remaining, message) = Self::smb_from_bytes(bytes)
            .map_err(|_e| nom::Err::Error(nom::error::ParseError::from_error_kind(bytes, ErrorKind::MapRes)))?;
        let command = message.command_code();
        // .map_err(|_e| );
        Ok((remaining, (message, command)))
    }

    fn sender(&self) -> SMBSender;
}