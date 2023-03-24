use std::str;

use nom::bytes::complete::{take, take_till};
use nom::error::ErrorKind;
use nom::IResult;
use nom::multi::many1;
use nom::number::complete::le_u8;
use serde::{Deserialize, Serialize};

use crate::protocol::body::Body;
use crate::protocol::body::negotiate::{SMBNegotiateRequest, SMBNegotiateResponse};
use crate::protocol::body::session_setup::{SMBSessionSetupRequestBody, SMBSessionSetupResponseBody};
use crate::protocol::header::LegacySMBCommandCode;
use crate::protocol::header::LegacySMBHeader;
use crate::protocol::header::SMBCommandCode;
use crate::protocol::header::SMBSyncHeader;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum SMBBody {
    None,
    NegotiateRequest(SMBNegotiateRequest),
    NegotiateResponse(SMBNegotiateResponse),
    SessionSetupRequest(SMBSessionSetupRequestBody),
    SessionSetupResponse(SMBSessionSetupResponseBody),
    LegacyCommand(LegacySMBBody)
}

impl Body<SMBSyncHeader> for SMBBody {

    fn parse_with_cc(bytes: &[u8], command_code: SMBCommandCode) -> IResult<&[u8], Self> {
        match command_code {
            SMBCommandCode::Negotiate => {
                let (remaining, body) = SMBNegotiateRequest::parse(bytes)?;
                Ok((remaining, SMBBody::NegotiateRequest(body)))
            },
            SMBCommandCode::SessionSetup => {
                let (remaining, body) = SMBSessionSetupRequestBody::parse(bytes)?;
                Ok((remaining, SMBBody::SessionSetupRequest(body)))
            }
            _ => Err(nom::Err::Error(nom::error::Error::new(bytes, ErrorKind::Fail))),
        }
    }

    fn as_bytes(&self) -> Vec<u8> {
        match self {
            SMBBody::NegotiateResponse(x) => {
                x.as_bytes()
            },
            SMBBody::SessionSetupResponse(x) => {
                x.as_bytes()
            }
            _ => Vec::new()
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum LegacySMBBody {
    None,
    Negotiate(Vec<String>)
}

impl Body<LegacySMBHeader> for LegacySMBBody {
    fn parse_with_cc(bytes: &[u8], command_code: LegacySMBCommandCode) -> IResult<&[u8], Self> where Self: Sized {
       match command_code {
           LegacySMBCommandCode::Negotiate => {
               let (remaining, cnt) = le_u8(bytes)?;
               let (_, protocol_vecs) = many1(take_till(|n: u8| n == 0x02))(remaining)?;
               let mut protocol_strs = Vec::new();
                for slice in protocol_vecs {
                    let mut vec = slice.to_vec();
                    vec.retain(|x| *x != 0);
                    protocol_strs.push(String::from_utf8(vec).map_err(
                        |_| nom::Err::Error(nom::error::Error::new(bytes, ErrorKind::Fail))
                    )?);
                }
               let (remaining, _) = take(cnt as usize)(bytes)?;
               Ok((remaining, LegacySMBBody::Negotiate(protocol_strs)))
           }
           _ => Err(nom::Err::Error(nom::error::Error::new(bytes, ErrorKind::Fail))),
       }
    }

    fn as_bytes(&self) -> Vec<u8> {
        todo!()
    }
}
