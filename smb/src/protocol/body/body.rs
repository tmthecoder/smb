use std::str;

use nom::bytes::complete::{take, take_till};
use nom::multi::many1;
use nom::number::complete::le_u8;
use serde::{Deserialize, Serialize};

use smb_core::{SMBFromBytes, SMBParseResult, SMBToBytes};
use smb_core::error::SMBError;

use crate::protocol::body::Body;
use crate::protocol::body::negotiate::{SMBNegotiateRequest, SMBNegotiateResponse};
use crate::protocol::body::session_setup::{SMBSessionSetupRequest, SMBSessionSetupResponse};
use crate::protocol::header::LegacySMBCommandCode;
use crate::protocol::header::LegacySMBHeader;
use crate::protocol::header::SMBCommandCode;
use crate::protocol::header::SMBSyncHeader;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum SMBBody {
    None,
    NegotiateRequest(SMBNegotiateRequest),
    NegotiateResponse(SMBNegotiateResponse),
    SessionSetupRequest(SMBSessionSetupRequest),
    SessionSetupResponse(SMBSessionSetupResponse),
    LegacyCommand(LegacySMBBody),
}

impl Body<SMBSyncHeader> for SMBBody {
    fn parse_with_cc(bytes: &[u8], command_code: SMBCommandCode) -> SMBParseResult<&[u8], Self> {
        match command_code {
            SMBCommandCode::Negotiate => {
                let (remaining, body) = SMBNegotiateRequest::smb_from_bytes(bytes)?;
                // println!("Test: {:?}", SMBNegotiateRequest::smb_from_bytes(bytes).unwrap());
                // println!("Actu: {:?}", body);
                Ok((remaining, SMBBody::NegotiateRequest(body)))
            },
            SMBCommandCode::SessionSetup => {
                let (remaining, body) = SMBSessionSetupRequest::smb_from_bytes(bytes)?;
                // println!("Actu: {:?} {:?}", remaining, body);
                // println!("Test: {:?}", SMBSessionSetupRequest::smb_from_bytes(bytes).unwrap());
                Ok((remaining, SMBBody::SessionSetupRequest(body)))
            }
            _ => Err(SMBError::ParseError("Unknown body parse failure")),
        }
    }

    fn as_bytes(&self) -> Vec<u8> {
        match self {
            SMBBody::NegotiateResponse(x) => {
                x.smb_to_bytes()
            },
            SMBBody::SessionSetupResponse(x) => {
                x.smb_to_bytes()
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
    fn parse_with_cc(bytes: &[u8], command_code: LegacySMBCommandCode) -> SMBParseResult<&[u8], Self> where Self: Sized {
        match command_code {
            LegacySMBCommandCode::Negotiate => {
                let (remaining, cnt) = le_u8(bytes)
                    .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| SMBError::ParseError("Invalid count"))?;
                let (_, protocol_vecs) = many1(take_till(|n: u8| n == 0x02))(remaining)
                    .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| SMBError::ParseError("No valid payload"))?;
                let mut protocol_strs = Vec::new();
                for slice in protocol_vecs {
                    let mut vec = slice.to_vec();
                    vec.retain(|x| *x != 0);
                    protocol_strs.push(String::from_utf8(vec).map_err(
                        |_| SMBError::ParseError("Could not map protocol to string")
                    )?);
                }
                let (remaining, _) = take(cnt as usize)(bytes)
                    .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| SMBError::ParseError("Size too small for parse length"))?;
                Ok((remaining, LegacySMBBody::Negotiate(protocol_strs)))
            }
            _ => Err(SMBError::ParseError("Unknown parse error for LegacySMBBody")),
       }
    }

    fn as_bytes(&self) -> Vec<u8> {
        todo!()
    }
}
