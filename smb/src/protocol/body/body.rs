use std::str;

use nom::bytes::complete::{take, take_till};
use nom::multi::many1;
use nom::number::complete::le_u8;
use serde::{Deserialize, Serialize};

use smb_core::{SMBByteSize, SMBEnumFromBytes, SMBFromBytes, SMBParseResult, SMBToBytes};
use smb_core::error::SMBError;
use smb_derive::{SMBEnumFromBytes, SMBToBytes};

use crate::protocol::body::Body;
use crate::protocol::body::logoff::{SMBLogoffRequest, SMBLogoffResponse};
use crate::protocol::body::negotiate::{SMBNegotiateRequest, SMBNegotiateResponse};
use crate::protocol::body::session_setup::{SMBSessionSetupRequest, SMBSessionSetupResponse};
use crate::protocol::body::tree_connect::{SMBTreeConnectRequest, SMBTreeConnectResponse};
use crate::protocol::body::tree_disconnect::{SMBTreeDisconnectRequest, SMBTreeDisconnectResponse};
use crate::protocol::header::LegacySMBCommandCode;
use crate::protocol::header::LegacySMBHeader;
use crate::protocol::header::SMBCommandCode;
use crate::protocol::header::SMBSyncHeader;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBEnumFromBytes, SMBToBytes)]
pub enum SMBBody {
    #[smb_discriminator(value = 0x0)]
    #[smb_direct(start(fixed = 0))]
    NegotiateRequest(SMBNegotiateRequest),
    #[smb_discriminator(value = 0x994)]
    #[smb_direct(start(fixed = 0))]
    NegotiateResponse(SMBNegotiateResponse),
    #[smb_discriminator(value = 0x1)]
    #[smb_direct(start(fixed = 0))]
    SessionSetupRequest(SMBSessionSetupRequest),
    #[smb_discriminator(value = 0x995)]
    #[smb_direct(start(fixed = 0))]
    SessionSetupResponse(SMBSessionSetupResponse),
    #[smb_discriminator(value = 0x4)]
    #[smb_direct(start(fixed = 0))]
    TreeConnectRequest(SMBTreeConnectRequest),
    #[smb_discriminator(value = 0x996)]
    #[smb_direct(start(fixed = 0))]
    TreeConnectResponse(SMBTreeConnectResponse),
    #[smb_discriminator(value = 0x2)]
    #[smb_direct(start(fixed = 0))]
    LogoffRequest(SMBLogoffRequest),
    #[smb_discriminator(value = 0x997)]
    #[smb_direct(start(fixed = 0))]
    LogoffResponse(SMBLogoffResponse),
    #[smb_discriminator(value = 0x4)]
    #[smb_direct(start(fixed = 0))]
    TreeDisconnectRequest(SMBTreeDisconnectRequest),
    #[smb_discriminator(value = 0x998)]
    #[smb_direct(start(fixed = 0))]
    TreeDisconnectResponse(SMBTreeDisconnectResponse),
    #[smb_discriminator(value = 0x999)]
    #[smb_enum(start(fixed = 0), discriminator(inner(start = 0, num_type = "u8")))]
    LegacyCommand(LegacySMBBody),
}

impl SMBByteSize for SMBBody {
    fn smb_byte_size(&self) -> usize {
        match self {
            SMBBody::NegotiateRequest(x) => x.smb_byte_size(),
            SMBBody::NegotiateResponse(x) => x.smb_byte_size(),
            SMBBody::SessionSetupRequest(x) => x.smb_byte_size(),
            SMBBody::SessionSetupResponse(x) => x.smb_byte_size(),
            SMBBody::TreeConnectRequest(x) => x.smb_byte_size(),
            SMBBody::TreeConnectResponse(x) => x.smb_byte_size(),
            SMBBody::LogoffRequest(x) => x.smb_byte_size(),
            SMBBody::LogoffResponse(x) => x.smb_byte_size(),
            SMBBody::TreeDisconnectRequest(x) => x.smb_byte_size(),
            SMBBody::TreeDisconnectResponse(x) => x.smb_byte_size(),
            SMBBody::LegacyCommand(x) => x.smb_byte_size(),
        }
    }
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
            },
            SMBCommandCode::LogOff => {
                let (remaining, body) = SMBLogoffRequest::smb_from_bytes(bytes)?;
                Ok((remaining, SMBBody::LogoffRequest(body)))
            },
            SMBCommandCode::TreeConnect => {
                let (remaining, body) = SMBTreeConnectRequest::smb_from_bytes(bytes)?;
                Ok((remaining, SMBBody::TreeConnectRequest(body)))
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
            },
            SMBBody::LogoffResponse(x) => {
                x.smb_to_bytes()
            },
            SMBBody::TreeConnectResponse(x) => x.smb_to_bytes(),
            _ => Vec::new()
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum LegacySMBBody {
    None,
    Negotiate(Vec<String>)
}

impl SMBEnumFromBytes for LegacySMBBody {
    fn smb_enum_from_bytes(input: &[u8], discriminator: u64) -> SMBParseResult<&[u8], Self> where Self: Sized {
        match LegacySMBCommandCode::try_from(discriminator as u8).map(|x| x == LegacySMBCommandCode::Negotiate) {
            Ok(true) => {
                let (remaining, cnt) = le_u8(input)
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
                let (remaining, _) = take(cnt as usize)(input)
                    .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| SMBError::ParseError("Size too small for parse length"))?;
                Ok((remaining, LegacySMBBody::Negotiate(protocol_strs)))
            },
            _ => Err(SMBError::ParseError("Unknown parse error for LegacySMBBody")),
        }
    }
}

impl SMBToBytes for LegacySMBBody {
    fn smb_to_bytes(&self) -> Vec<u8> {
        todo!()
    }
}

impl SMBByteSize for LegacySMBBody {
    fn smb_byte_size(&self) -> usize {
        match self {
            LegacySMBBody::None => 0,
            LegacySMBBody::Negotiate(x) => x.len() * 2
        }
    }
}

impl Body<LegacySMBHeader> for LegacySMBBody {
    fn parse_with_cc(bytes: &[u8], command_code: LegacySMBCommandCode) -> SMBParseResult<&[u8], Self> where Self: Sized {
        LegacySMBBody::smb_enum_from_bytes(bytes, command_code as u64)
    }

    fn as_bytes(&self) -> Vec<u8> {
        todo!()
    }
}
