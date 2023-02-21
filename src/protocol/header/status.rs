use nom::bits::streaming::take;
use nom::combinator::{map_res, map};
use nom::error::{ErrorKind, make_error};
use nom::number::complete::le_u8;
use nom::number::streaming::le_u16;
use nom::sequence::tuple;
use nom::{bits, IResult};
use nom::Err::Error;
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use crate::byte_helper::{bytes_to_u16, u16_to_bytes};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum SMBStatus {
    NTStatus(NTStatusCode),
    DosError(char, char, u16),
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct NTStatusCode {
    level: NTStatusLevel,
    facility: [u8; 2],
    error_code: u16,
}

#[repr(u8)]
#[derive(Serialize, Deserialize, TryFromPrimitive, PartialEq, Eq, Debug, Copy, Clone)]
pub enum NTStatusLevel {
    Success = 0x0,
    Information,
    Warning,
    Error,
}

impl SMBStatus {
    pub(crate) fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
       bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((take(4_usize), take(4_usize))))(bytes)
            .and_then(|(_, (_, nibble)): (&[u8], (u8, u8))| {
                if nibble == 0x0 || nibble == 0x4 || nibble == 0x8 || nibble == 0xC {
                    let level = NTStatusLevel::try_from(nibble >> 2).map_err(|e| Error(nom::error::Error::new(bytes, ErrorKind::Fail)))?;
                    let (remaining, facility) = map(nom::bytes::complete::take(2_usize), |s: &[u8]| [s[0] << 4, s[1]])(bytes)?;
                    let (remaining, error_code) = le_u16(remaining)?;
                    Ok((remaining, Self::NTStatus(NTStatusCode {
                        level,
                        facility,
                        error_code
                    })))
                } else {
                    map(
                        tuple((le_u8, le_u8, le_u16)),
                        |(first, second, third)| Self::DosError(first.into(), second.into(), third)
                    )(bytes)
                }
            })?;
        todo!()
    }
}

impl SMBStatus {
    pub(crate) fn as_bytes(&self) -> Vec<u8> {
        match self {
            SMBStatus::NTStatus(x) => [
                &[((x.level as u8) << 4_u8) + x.facility[0]][0..],
                &[x.facility[1]][0..],
                &u16_to_bytes(x.error_code)[0..],
            ]
            .concat(),
            SMBStatus::DosError(c1, c2, code) => [
                &[*c1 as u8][0..],
                &[*c2 as u8][0..],
                &u16_to_bytes(*code)[0..],
            ]
            .concat(),
        }
    }
}

