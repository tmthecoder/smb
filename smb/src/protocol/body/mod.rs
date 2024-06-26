use std::str;

use nom::bytes::complete::{take, take_till};
use nom::multi::many1;
use nom::number::complete::le_u8;
use serde::{Deserialize, Serialize};

use smb_core::{SMBByteSize, SMBEnumFromBytes, SMBFromBytes, SMBParseResult, SMBToBytes};
use smb_core::error::SMBError;
use smb_derive::{SMBByteSize, SMBEnumFromBytes, SMBToBytes};

use crate::protocol::body::cancel::SMBCancelRequest;
use crate::protocol::body::change_notify::{SMBChangeNotifyRequest, SMBChangeNotifyResponse};
use crate::protocol::body::close::{SMBCloseRequest, SMBCloseResponse};
use crate::protocol::body::create::{SMBCreateRequest, SMBCreateResponse};
use crate::protocol::body::echo::{SMBEchoRequest, SMBEchoResponse};
use crate::protocol::body::flush::{SMBFlushRequest, SMBFlushResponse};
use crate::protocol::body::ioctl::{SMBIoCtlRequest, SMBIoCtlResponse};
use crate::protocol::body::lock::{SMBLockRequest, SMBLockResponse};
use crate::protocol::body::logoff::{SMBLogoffRequest, SMBLogoffResponse};
use crate::protocol::body::negotiate::{SMBNegotiateRequest, SMBNegotiateResponse};
use crate::protocol::body::oplock_break::{SMBOplockBreakAcknowledgement, SMBOplockBreakContent};
use crate::protocol::body::query_directory::{SMBQueryDirectoryRequest, SMBQueryDirectoryResponse};
use crate::protocol::body::query_info::{SMBQueryInfoRequest, SMBQueryInfoResponse};
use crate::protocol::body::read::{SMBReadRequest, SMBReadResponse};
use crate::protocol::body::session_setup::{SMBSessionSetupRequest, SMBSessionSetupResponse};
use crate::protocol::body::set_info::{SMBSetInfoRequest, SMBSetInfoResponse};
use crate::protocol::body::tree_connect::{SMBTreeConnectRequest, SMBTreeConnectResponse};
use crate::protocol::body::tree_disconnect::{SMBTreeDisconnectRequest, SMBTreeDisconnectResponse};
use crate::protocol::body::write::{SMBWriteRequest, SMBWriteResponse};
use crate::protocol::header::command_code::{LegacySMBCommandCode, SMBCommandCode};
use crate::protocol::header::Header;
use crate::protocol::header::LegacySMBHeader;
use crate::protocol::header::SMBSyncHeader;

pub mod capabilities;
pub mod dialect;
pub mod filetime;
pub mod negotiate;
pub mod session_setup;

pub mod logoff;
pub mod tree_connect;
pub mod tree_disconnect;
pub mod empty;
pub mod create;
mod error;
pub mod close;
pub mod flush;
pub mod read;
pub mod write;
pub mod lock;
pub mod echo;
pub mod cancel;
pub mod query_directory;
pub mod change_notify;
pub mod query_info;
pub mod ioctl;
pub mod set_info;
pub mod oplock_break;

pub trait Body<S: Header>: SMBEnumFromBytes + SMBToBytes {
    fn parse_with_cc(bytes: &[u8], command_code: S::CommandCode) -> SMBParseResult<&[u8], Self> where Self: Sized;
    fn as_bytes(&self) -> Vec<u8>;
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBEnumFromBytes, SMBToBytes, SMBByteSize)]
pub enum SMBBody {
    #[smb_discriminator(value = 0x0)]
    #[smb_direct(start(fixed = 0))]
    NegotiateRequest(SMBNegotiateRequest),
    #[smb_discriminator(value = 0x0)]
    #[smb_discriminator(flag = 0x10000)]
    #[smb_direct(start(fixed = 0))]
    NegotiateResponse(SMBNegotiateResponse),
    #[smb_discriminator(value = 0x1)]
    #[smb_direct(start(fixed = 0))]
    SessionSetupRequest(SMBSessionSetupRequest),
    #[smb_discriminator(value = 0x1)]
    #[smb_discriminator(flag = 0x10000)]
    #[smb_direct(start(fixed = 0))]
    SessionSetupResponse(SMBSessionSetupResponse),
    #[smb_discriminator(value = 0x3)]
    #[smb_direct(start(fixed = 0))]
    TreeConnectRequest(SMBTreeConnectRequest),
    #[smb_discriminator(value = 0x3)]
    #[smb_discriminator(flag = 0x10000)]
    #[smb_direct(start(fixed = 0))]
    TreeConnectResponse(SMBTreeConnectResponse),
    #[smb_discriminator(value = 0x2)]
    #[smb_direct(start(fixed = 0))]
    LogoffRequest(SMBLogoffRequest),
    #[smb_discriminator(value = 0x2)]
    #[smb_discriminator(flag = 0x10000)]
    #[smb_direct(start(fixed = 0))]
    LogoffResponse(SMBLogoffResponse),
    #[smb_discriminator(value = 0x4)]
    #[smb_direct(start(fixed = 0))]
    TreeDisconnectRequest(SMBTreeDisconnectRequest),
    #[smb_discriminator(value = 0x4)]
    #[smb_discriminator(flag = 0x10000)]
    #[smb_direct(start(fixed = 0))]
    TreeDisconnectResponse(SMBTreeDisconnectResponse),
    #[smb_discriminator(value = 0x5)]
    #[smb_direct(start(fixed = 0))]
    CreateRequest(SMBCreateRequest),
    #[smb_discriminator(value = 0x5)]
    #[smb_discriminator(flag = 0x10000)]
    #[smb_direct(start(fixed = 0))]
    CreateResponse(SMBCreateResponse),
    #[smb_discriminator(value = 0x6)]
    #[smb_direct(start(fixed = 0))]
    CloseRequest(SMBCloseRequest),
    #[smb_discriminator(value = 0x6)]
    #[smb_discriminator(flag = 0x10000)]
    #[smb_direct(start(fixed = 0))]
    CloseResponse(SMBCloseResponse),
    #[smb_discriminator(value = 0x7)]
    #[smb_direct(start(fixed = 0))]
    FlushRequest(SMBFlushRequest),
    #[smb_discriminator(value = 0x7)]
    #[smb_discriminator(flag = 0x10000)]
    #[smb_direct(start(fixed = 0))]
    FlushResponse(SMBFlushResponse),
    #[smb_discriminator(value = 0x8)]
    #[smb_direct(start(fixed = 0))]
    ReadRequest(SMBReadRequest),
    #[smb_discriminator(value = 0x8)]
    #[smb_discriminator(flag = 0x10000)]
    #[smb_direct(start(fixed = 0))]
    ReadResponse(SMBReadResponse),
    #[smb_discriminator(value = 0x9)]
    #[smb_direct(start(fixed = 0))]
    WriteRequest(SMBWriteRequest),
    #[smb_discriminator(value = 0x9)]
    #[smb_discriminator(flag = 0x10000)]
    #[smb_direct(start(fixed = 0))]
    WriteResponse(SMBWriteResponse),
    #[smb_discriminator(value = 0xA)]
    #[smb_direct(start(fixed = 0))]
    LockRequest(SMBLockRequest),
    #[smb_discriminator(value = 0xA)]
    #[smb_discriminator(flag = 0x10000)]
    #[smb_direct(start(fixed = 0))]
    LockResponse(SMBLockResponse),
    #[smb_discriminator(value = 0xB)]
    #[smb_direct(start(fixed = 0))]
    IoCtlRequest(SMBIoCtlRequest),
    #[smb_discriminator(value = 0xB)]
    #[smb_discriminator(flag = 0x10000)]
    #[smb_direct(start(fixed = 0))]
    IoCtlResponse(SMBIoCtlResponse),
    #[smb_discriminator(value = 0xC)]
    #[smb_direct(start(fixed = 0))]
    CancelRequest(SMBCancelRequest),
    #[smb_discriminator(value = 0xD)]
    #[smb_direct(start(fixed = 0))]
    EchoRequest(SMBEchoRequest),
    #[smb_discriminator(value = 0xD)]
    #[smb_discriminator(flag = 0x10000)]
    #[smb_direct(start(fixed = 0))]
    EchoResponse(SMBEchoResponse),
    #[smb_discriminator(value = 0xE)]
    #[smb_direct(start(fixed = 0))]
    QueryDirectoryRequest(SMBQueryDirectoryRequest),
    #[smb_discriminator(value = 0xE)]
    #[smb_discriminator(flag = 0x10000)]
    #[smb_direct(start(fixed = 0))]
    QueryDirectoryResponse(SMBQueryDirectoryResponse),
    #[smb_discriminator(value = 0xF)]
    #[smb_direct(start(fixed = 0))]
    ChangeNotifyRequest(SMBChangeNotifyRequest),
    #[smb_discriminator(value = 0xF)]
    #[smb_discriminator(flag = 0x10000)]
    #[smb_direct(start(fixed = 0))]
    ChangeNotifyResponse(SMBChangeNotifyResponse),
    #[smb_discriminator(value = 0x10)]
    #[smb_direct(start(fixed = 0))]
    QueryInfoRequest(SMBQueryInfoRequest),
    #[smb_discriminator(value = 0x10)]
    #[smb_discriminator(flag = 0x10000)]
    #[smb_direct(start(fixed = 0))]
    QueryInfoResponse(SMBQueryInfoResponse),
    #[smb_discriminator(value = 0x11)]
    #[smb_direct(start(fixed = 0))]
    SetInfoRequest(SMBSetInfoRequest),
    #[smb_discriminator(value = 0x11)]
    #[smb_discriminator(flag = 0x10000)]
    #[smb_direct(start(fixed = 0))]
    SetInfoResponse(SMBSetInfoResponse),
    #[smb_discriminator(value = 0x12)]
    #[smb_direct(start(fixed = 0))]
    OplockBreak(SMBOplockBreakContent),
    #[smb_discriminator(value = 0x12)]
    #[smb_discriminator(flag = 0x10000)]
    #[smb_direct(start(fixed = 0))]
    OplockBreakAcknowledgement(SMBOplockBreakAcknowledgement),
    #[smb_discriminator(value = 0x999)]
    #[smb_enum(start(fixed = 0), discriminator(inner(start = 0, num_type = "u8")))]
    LegacyCommand(LegacySMBBody),
}

impl Body<SMBSyncHeader> for SMBBody {
    fn parse_with_cc(bytes: &[u8], command_code: SMBCommandCode) -> SMBParseResult<&[u8], Self> {
        Self::smb_enum_from_bytes(bytes, command_code as u64)
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.smb_to_bytes()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum LegacySMBBody {
    None,
    Negotiate(Vec<String>),
}

impl smb_core::SMBEnumFromBytes for LegacySMBBody {
    fn smb_enum_from_bytes(input: &[u8], discriminator: u64) -> SMBParseResult<&[u8], Self> where Self: Sized {
        match LegacySMBCommandCode::try_from(discriminator as u8).map(|x| x == LegacySMBCommandCode::Negotiate) {
            Ok(true) => {
                let (remaining, cnt) = le_u8(input)
                    .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| SMBError::parse_error("Invalid count"))?;
                let (_, protocol_vecs) = many1(take_till(|n: u8| n == 0x02))(remaining)
                    .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| SMBError::parse_error("No valid payload"))?;
                let mut protocol_strs = Vec::new();
                for slice in protocol_vecs {
                    let mut vec = slice.to_vec();
                    vec.retain(|x| *x != 0);
                    protocol_strs.push(String::from_utf8(vec).map_err(
                        |_| SMBError::parse_error("Could not map protocol to string"))?
                    );
                }
                let (remaining, _) = take(cnt as usize)(input)
                    .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| SMBError::parse_error("Size too small for parse length"))?;
                Ok((remaining, LegacySMBBody::Negotiate(protocol_strs)))
            },
            _ => Err(SMBError::parse_error("Unknown parse error for LegacySMBBody")),
        }
    }
}

impl smb_core::SMBToBytes for LegacySMBBody {
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
        self.smb_to_bytes()
    }
}