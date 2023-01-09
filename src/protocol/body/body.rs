use serde::{Deserialize, Serialize};
use std::str;
use nom::error::ErrorKind;
use nom::IResult;
use crate::protocol::body::Body;
use crate::protocol::body::negotiate::{SMBNegotiateRequest, SMBNegotiateResponse};
use crate::protocol::body::session_setup::{SMBSessionSetupRequestBody, SMBSessionSetupResponseBody};
use crate::protocol::header::{LegacySMBCommandCode, LegacySMBHeader, SMBCommandCode, SMBSyncHeader};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum SMBBody {
    None,
    NegotiateRequest(SMBNegotiateRequest),
    NegotiateResponse(SMBNegotiateResponse),
    SessionSetupRequest(SMBSessionSetupRequestBody),
    SessionSetupResponse(SMBSessionSetupResponseBody),
    LegacyCommand(LegacySMBBody)
}

impl Body<SMBSyncHeader> for SMBBody {

    fn from_bytes_and_header_exists<'a>(bytes: &'a [u8], header: &SMBSyncHeader) -> IResult<&'a [u8], Self> {
        let body = Self::from_bytes_and_header(bytes, header);
        if body.1 == SMBBody::None {
            return Err(nom::Err::Error(nom::error::Error::new(body.0, ErrorKind::Fail)));
        }
        Ok(body)
    }

    fn from_bytes_and_header<'a>(bytes: &'a [u8], header: &SMBSyncHeader) -> (&'a [u8], Self) {
        match header.command {
            SMBCommandCode::Negotiate => {
                if let Some((negotiation_body, carryover)) = SMBNegotiateRequest::from_bytes(bytes) {
                    return (carryover, SMBBody::NegotiateRequest(negotiation_body))
                }
                (bytes, SMBBody::None)
            },
            SMBCommandCode::SessionSetup => {
                if let Some((session_setup_body, carryover)) = SMBSessionSetupRequestBody::from_bytes(bytes) {
                    return (carryover, SMBBody::SessionSetupRequest(session_setup_body))
                }
                (bytes, SMBBody::None)
            }
            _ => (bytes, SMBBody::None)
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

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum LegacySMBBody {
    None,
    Negotiate(Vec<String>)
}

impl Body<LegacySMBHeader> for LegacySMBBody {
    fn from_bytes_and_header_exists<'a>(bytes: &'a [u8], header: &LegacySMBHeader) -> IResult<&'a [u8], Self> {
        let body = Self::from_bytes_and_header(bytes, header);
        if body.1 == LegacySMBBody::None {
            return Err(nom::Err::Error(nom::error::Error::new(body.0, ErrorKind::Fail)));
        }
        Ok(body)
    }

    fn from_bytes_and_header<'a>(bytes: &'a [u8], header: &LegacySMBHeader) -> (&'a [u8], Self) {
        return match header.command {
            LegacySMBCommandCode::Negotiate => {
                let count = bytes[0] as usize;
                let sliver = &bytes[1..=count];
                println!("{:?}", sliver);
                let protocol_strs: Vec<String> = sliver.split(|num| *num == 0x02).filter_map(|mut protocol| {
                    if let Some(x) = protocol.last() {
                        if *x == 0 {
                            protocol = &protocol[0..(protocol.len() - 1)];
                        }
                        if protocol.is_empty() { return None; }
                        Some(str::from_utf8(protocol).ok()?.to_owned())
                    } else {
                        None
                    }
                }).collect();
                let body = LegacySMBBody::Negotiate(protocol_strs);
                (&bytes[(count + 1)..], body)
            },
            _ => (bytes, LegacySMBBody::None)
        }
    }

    fn as_bytes(&self) -> Vec<u8> {
        todo!()
    }
}