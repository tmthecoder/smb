//! SMB2 Packet Header definitions.
//!
//! Implements the SMB2 Packet Header as specified in
//! [\[MS-SMB2\] 2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5cd64522-60b3-4f3e-a157-fe66f1228052).
//!
//! Two header variants are provided:
//! - [`SMBSyncHeader`]: The synchronous (non-async) SMB2 header ([\[MS-SMB2\] 2.2.1.2]).
//! - [`LegacySMBHeader`]: The SMB1 header used only for initial legacy negotiate.

use std::cmp::min;
use std::marker::PhantomData;

use nom::error::ErrorKind;
use nom::IResult;
use serde::{Deserialize, Serialize};

use smb_core::{SMBFromBytes, SMBToBytes};
use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::header::command_code::{LegacySMBCommandCode, SMBCommandCode};
use crate::protocol::header::extra::SMBExtra;
use crate::protocol::header::flags::{LegacySMBFlags, SMBFlags};
use crate::protocol::header::flags2::LegacySMBFlags2;
use crate::protocol::header::status::SMBStatus;

/// SMB2 command codes ([\[MS-SMB2\] 2.2.1]).
pub mod command_code;
/// NT Status codes and legacy DOS error codes.
pub mod status;
/// SMB2 header flags ([\[MS-SMB2\] 2.2.1]: `Flags` field).
pub mod flags;
/// Legacy SMB1 Flags2 field.
pub mod flags2;
/// Legacy SMB1 header extra fields.
pub mod extra;

/// Indicates the direction of an SMB message.
///
/// Per [\[MS-SMB2\] 2.2.1], the `SMB2_FLAGS_SERVER_TO_REDIR` bit in the Flags field
/// distinguishes server responses (`Server`) from client requests (`Client`).
pub enum SMBSender {
    /// Message originates from a client (request).
    Client = 0x0,
    /// Message originates from the server (response).
    Server,
}

/// Common trait for all SMB packet headers.
///
/// Provides access to the command code and message direction. Both
/// [`SMBSyncHeader`] and [`LegacySMBHeader`] implement this trait.
pub trait Header: SMBFromBytes + SMBToBytes {
    /// The command code type (e.g. [`SMBCommandCode`] or [`LegacySMBCommandCode`]).
    type CommandCode: Into<u64>;

    /// Returns the command code from this header's `Command` field.
    fn command_code(&self) -> Self::CommandCode;

    /// Parse a header from raw bytes, returning the header and its command code.
    fn parse(bytes: &[u8]) -> IResult<&[u8], (Self, Self::CommandCode)> where Self: Sized + SMBFromBytes {
        let (remaining, message) = Self::smb_from_bytes(bytes)
            .map_err(|_e| nom::Err::Error(nom::error::ParseError::from_error_kind(bytes, ErrorKind::MapRes)))?;
        let command = message.command_code();
        // .map_err(|_e| );
        Ok((remaining, (message, command)))
    }

    /// Returns whether this message was sent by a client or server,
    /// based on the `SMB2_FLAGS_SERVER_TO_REDIR` flag.
    fn sender(&self) -> SMBSender;
}

/// SMB2 Packet Header — SYNC variant.
///
/// This is the 64-byte synchronous header used for all non-async SMB2/3 messages,
/// as defined in [\[MS-SMB2\] 2.2.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4).
///
/// ## Wire Format (64 bytes)
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0 | 4 | ProtocolId (`0xFE 'S' 'M' 'B'`) |
/// | 4 | 2 | StructureSize (64) |
/// | 6 | 2 | CreditCharge |
/// | 8 | 4 | (ChannelSequence/Reserved) or Status |
/// | 12 | 2 | Command |
/// | 14 | 2 | CreditRequest/CreditResponse |
/// | 16 | 4 | Flags |
/// | 20 | 4 | NextCommand |
/// | 24 | 8 | MessageId |
/// | 32 | 4 | Reserved (0xFFFE0000) |
/// | 36 | 4 | TreeId |
/// | 40 | 8 | SessionId |
/// | 48 | 16 | Signature |
#[derive(
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Debug,
    SMBFromBytes,
    SMBToBytes,
    SMBByteSize,
    Clone
)]
#[smb_byte_tag(value = 0xFE, order = 0)]
#[smb_string_tag(value = "SMB", order = 1)]
#[smb_byte_tag(value = 64, order = 2)]
pub struct SMBSyncHeader {
    #[smb_direct(start(fixed = 8))]
    pub channel_sequence: u32,
    #[smb_direct(start(fixed = 12))]
    pub command: SMBCommandCode,
    #[smb_direct(start(fixed = 14))]
    pub credits: u16,
    #[smb_direct(start(fixed = 16))]
    pub flags: SMBFlags,
    #[smb_direct(start(fixed = 20))]
    pub next_command: u32,
    #[smb_direct(start(fixed = 24))]
    pub message_id: u64,
    #[smb_skip(start = 32, length = 4, value = "[0xFF, 0xFE, 0, 0]")]
    pub reserved: PhantomData<[u8; 4]>,
    #[smb_direct(start(fixed = 36))]
    pub tree_id: u32,
    #[smb_direct(start(fixed = 40))]
    pub session_id: u64,
    #[smb_direct(start(fixed = 48))]
    pub signature: [u8; 16],
}

/// Legacy SMB1 header, used only for the initial SMB1 Negotiate request
/// that triggers dialect upgrade to SMB2.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, SMBFromBytes, SMBByteSize, SMBToBytes)]
#[smb_byte_tag(value = 0xFE)]
#[smb_string_tag("SMB")]
pub struct LegacySMBHeader {
    #[smb_direct(start(fixed = 4))]
    pub(crate) command: LegacySMBCommandCode,
    #[smb_direct(start(fixed = 5))]
    status: SMBStatus,
    #[smb_direct(start(fixed = 9))]
    flags: LegacySMBFlags,
    #[smb_direct(start(fixed = 10))]
    flags2: LegacySMBFlags2,
    #[smb_direct(start(fixed = 12))]
    extra: SMBExtra,
    #[smb_direct(start(fixed = 22))]
    tid: u16,
    #[smb_direct(start(fixed = 24))]
    pid: u16,
    #[smb_direct(start(fixed = 26))]
    uid: u16,
    #[smb_direct(start(fixed = 28))]
    mid: u16,
}

impl Header for SMBSyncHeader {
    type CommandCode = SMBCommandCode;

    fn command_code(&self) -> Self::CommandCode {
        self.command
    }

    fn sender(&self) -> SMBSender {
        if self.flags.contains(SMBFlags::SERVER_TO_REDIR) {
            SMBSender::Server
        } else {
            SMBSender::Client
        }
    }
}

impl Header for LegacySMBHeader {
    type CommandCode = LegacySMBCommandCode;

    fn command_code(&self) -> Self::CommandCode {
        self.command
    }

    fn sender(&self) -> SMBSender {
        if self.flags.contains(LegacySMBFlags::SERVER_TO_REDIR) {
            SMBSender::Server
        } else {
            SMBSender::Client
        }
    }
}

impl SMBSyncHeader {
    /// Construct a new sync header with the given field values.
    ///
    /// `channel_sequence` and `credits` default to 0.
    pub fn new(
        command: SMBCommandCode,
        flags: SMBFlags,
        next_command: u32,
        message_id: u64,
        tree_id: u32,
        session_id: u64,
        signature: [u8; 16],
    ) -> Self {
        SMBSyncHeader {
            command,
            channel_sequence: 0,
            credits: 0,
            flags,
            next_command,
            message_id,
            reserved: PhantomData,
            tree_id,
            session_id,
            signature,
        }
    }

    /// Convert a legacy SMB1 Negotiate header into an SMB2 sync header.
    ///
    /// Returns `None` if the legacy command is not `Negotiate`.
    pub fn from_legacy_header(legacy_header: LegacySMBHeader) -> Option<Self> {
        match legacy_header.command {
            LegacySMBCommandCode::Negotiate => Some(Self {
                command: SMBCommandCode::LegacyNegotiate,
                flags: SMBFlags::empty(),
                channel_sequence: 0,
                next_command: 0,
                credits: 0,
                message_id: legacy_header.mid as u64,
                reserved: PhantomData,
                tree_id: legacy_header.tid as u32,
                session_id: legacy_header.uid as u64,
                signature: [0; 16],
            }),
            _ => None,
        }
    }

    /// Create a response header from this request header.
    ///
    /// Sets `SMB2_FLAGS_SERVER_TO_REDIR`, copies the command and message ID,
    /// and zeroes the signature (to be filled in later if signing is required).
    pub fn create_response_header(&self, channel_sequence: u32, session_id: u64, tree_id: u32) -> Self {
        Self {
            command: self.command,
            flags: SMBFlags::SERVER_TO_REDIR,
            channel_sequence,
            next_command: 0,
            credits: self.credits,
            message_id: self.message_id,
            reserved: PhantomData,
            tree_id,
            session_id,
            signature: [0; 16],
        }
    }

    /// Set the message signature and enable the `SMB2_FLAGS_SIGNED` flag.
    ///
    /// Copies up to 16 bytes from `signature` into the header's Signature field.
    pub fn set_signature(&mut self, signature: &[u8]) {
        self.flags |= SMBFlags::SIGNED;
        self.signature[..min(16, signature.len())]
            .copy_from_slice(&signature[..min(16, signature.len())]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBFromBytes, SMBToBytes};

    #[test]
    fn sync_header_protocol_id_and_structure_size() {
        let header = SMBSyncHeader::new(
            SMBCommandCode::Negotiate, SMBFlags::empty(), 0, 0, 0, 0, [0; 16],
        );
        let bytes = header.smb_to_bytes();
        assert_eq!(bytes[0], 0xFE);
        assert_eq!(bytes[1], b'S');
        assert_eq!(bytes[2], b'M');
        assert_eq!(bytes[3], b'B');
        assert_eq!(bytes[4], 64);
        assert_eq!(bytes[5], 0);
    }

    #[test]
    fn sync_header_is_64_bytes() {
        let header = SMBSyncHeader::new(
            SMBCommandCode::Echo, SMBFlags::empty(), 0, 0, 0, 0, [0; 16],
        );
        assert_eq!(header.smb_to_bytes().len(), 64);
    }

    #[test]
    fn sync_header_command_field_offset() {
        let header = SMBSyncHeader::new(
            SMBCommandCode::SessionSetup, SMBFlags::empty(), 0, 0, 0, 0, [0; 16],
        );
        let bytes = header.smb_to_bytes();
        let cmd = u16::from_le_bytes([bytes[12], bytes[13]]);
        assert_eq!(cmd, 0x0001);
    }

    #[test]
    fn sync_header_flags_field_offset() {
        let header = SMBSyncHeader::new(
            SMBCommandCode::Negotiate,
            SMBFlags::SERVER_TO_REDIR | SMBFlags::SIGNED,
            0, 0, 0, 0, [0; 16],
        );
        let bytes = header.smb_to_bytes();
        let flags = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        assert_eq!(flags & 0x01, 0x01);
        assert_eq!(flags & 0x08, 0x08);
    }

    #[test]
    fn sync_header_message_id_offset() {
        let header = SMBSyncHeader::new(
            SMBCommandCode::Echo, SMBFlags::empty(), 0, 42, 0, 0, [0; 16],
        );
        let bytes = header.smb_to_bytes();
        let msg_id = u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27],
            bytes[28], bytes[29], bytes[30], bytes[31],
        ]);
        assert_eq!(msg_id, 42);
    }

    #[test]
    fn sync_header_tree_id_and_session_id() {
        let header = SMBSyncHeader::new(
            SMBCommandCode::Create, SMBFlags::empty(), 0, 0, 0x1234, 0xABCD, [0; 16],
        );
        let bytes = header.smb_to_bytes();
        let tree_id = u32::from_le_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]);
        let session_id = u64::from_le_bytes([
            bytes[40], bytes[41], bytes[42], bytes[43],
            bytes[44], bytes[45], bytes[46], bytes[47],
        ]);
        assert_eq!(tree_id, 0x1234);
        assert_eq!(session_id, 0xABCD);
    }

    #[test]
    fn sync_header_signature_offset() {
        let sig = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let header = SMBSyncHeader::new(
            SMBCommandCode::Echo, SMBFlags::empty(), 0, 0, 0, 0, sig,
        );
        let bytes = header.smb_to_bytes();
        assert_eq!(&bytes[48..64], &sig);
    }

    #[test]
    fn sync_header_round_trip() {
        let header = SMBSyncHeader::new(
            SMBCommandCode::TreeConnect, SMBFlags::SERVER_TO_REDIR, 0, 7, 3, 99, [0xAA; 16],
        );
        let bytes = header.smb_to_bytes();
        let (remaining, parsed) = SMBSyncHeader::smb_from_bytes(&bytes).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(parsed.command, header.command);
        assert_eq!(parsed.flags, header.flags);
        assert_eq!(parsed.message_id, header.message_id);
        assert_eq!(parsed.tree_id, header.tree_id);
        assert_eq!(parsed.session_id, header.session_id);
        assert_eq!(parsed.signature, header.signature);
    }

    #[test]
    fn create_response_header_sets_server_flag() {
        let request = SMBSyncHeader::new(
            SMBCommandCode::Negotiate, SMBFlags::empty(), 0, 1, 0, 0, [0; 16],
        );
        let response = request.create_response_header(0, 0, 0);
        assert!(response.flags.contains(SMBFlags::SERVER_TO_REDIR));
        assert_eq!(response.command, SMBCommandCode::Negotiate);
        assert_eq!(response.message_id, 1);
    }

    #[test]
    fn set_signature_enables_signed_flag() {
        let mut header = SMBSyncHeader::new(
            SMBCommandCode::Echo, SMBFlags::empty(), 0, 0, 0, 0, [0; 16],
        );
        assert!(!header.flags.contains(SMBFlags::SIGNED));
        let sig = [0xDE; 16];
        header.set_signature(&sig);
        assert!(header.flags.contains(SMBFlags::SIGNED));
        assert_eq!(header.signature, sig);
    }
}
