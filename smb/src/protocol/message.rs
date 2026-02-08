//! SMB2 message framing and serialization.
//!
//! An SMB2 message on the wire is a **4-byte NetBIOS session header** (big-endian
//! length prefix) followed by the 64-byte SMB2 header and the variable-length body.
//!
//! This module provides:
//! - [`SMBMessage`]: Generic container pairing a [`Header`] with a [`Body`].
//! - [`Message`] trait: `as_bytes()` / `parse()` / `signature()` for wire I/O.
//! - Type aliases [`SMBSyncMessage`] and [`SMBLegacyMessage`].

use std::fmt::Debug;
use std::str;

use aes::Aes128;
use cmac::Cmac;
use digest::Mac;
use hmac::Hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use smb_core::{SMBFromBytes, SMBParseResult, SMBResult, SMBToBytes};
use smb_core::error::SMBError;
use smb_core::logging::trace;

use crate::byte_helper::u16_to_bytes;
use crate::protocol::body::{Body, LegacySMBBody, SMBBody};
use crate::protocol::body::negotiate::context::SigningAlgorithm;
use crate::protocol::header::{Header, LegacySMBHeader, SMBSyncHeader};

/// Convenience alias for a synchronous SMB2/3 message.
pub type SMBSyncMessage = SMBMessage<SMBSyncHeader, SMBBody>;
/// Convenience alias for a legacy SMB1 message.
pub type SMBLegacyMessage = SMBMessage<LegacySMBHeader, LegacySMBBody>;

/// An SMB message consisting of a header and a body.
///
/// The generic parameters allow this type to represent both SMB2 sync messages
/// ([`SMBSyncHeader`] + [`SMBBody`]) and legacy SMB1 messages.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct SMBMessage<S: Header, T: Body<S>> {
    /// The 64-byte SMB2 packet header (or legacy SMB1 header).
    pub header: S,
    /// The command-specific request or response body.
    pub body: T,
}

impl<S: Header, T: Body<S>> SMBMessage<S, T> {
    pub fn new(header: S, body: T) -> Self {
        SMBMessage {
            header,
            body
        }
    }
}

/// Trait for serializing, parsing, and signing SMB messages.
///
/// The wire format produced by [`as_bytes`](Message::as_bytes) is:
/// ```text
/// [0..2]  0x00 0x00          (padding)
/// [2..4]  big-endian u16     (length of SMB2 header + body)
/// [4..]   SMB2 header + body
/// ```
pub trait Message {
    /// Serialize this message to its wire-format bytes (including 4-byte NetBIOS header).
    fn as_bytes(&self) -> Vec<u8>;
    /// Parse a message from raw bytes (starting at the SMB2 ProtocolId, **without**
    /// the 4-byte NetBIOS header).
    fn parse(bytes: &[u8]) -> SMBParseResult<&[u8], Self> where Self: Sized;

    /// Compute the cryptographic signature for this message using the given
    /// signing key and algorithm ([\[MS-SMB2\] 3.1.5.1]).
    fn signature(&self, nonce: &[u8], key: &[u8], algorithm: SigningAlgorithm) -> SMBResult<Vec<u8>>;
}

impl SMBMessage<SMBSyncHeader, SMBBody> {
    /// Convert a legacy SMB1 message into an SMB2 sync message.
    ///
    /// Used during dialect negotiation when the client sends an SMB1 Negotiate
    /// that must be upgraded to SMB2.
    pub fn from_legacy(legacy_message: SMBMessage<LegacySMBHeader, LegacySMBBody>) -> Option<Self> {
        let header = SMBSyncHeader::from_legacy_header(legacy_message.header)?;
        let body = SMBBody::LegacyCommand(legacy_message.body);
        Some(Self { header, body })
    }
}

impl<S: Header + Debug, T: Body<S>> Message for SMBMessage<S, T> {
    fn as_bytes(&self) -> Vec<u8> {
        let smb2_message = [self.header.smb_to_bytes(), self.body.smb_to_bytes()].concat();
        let mut len_bytes = u16_to_bytes(smb2_message.len() as u16);
        len_bytes.reverse();
        [[0, 0].to_vec(), len_bytes.to_vec(), smb2_message].concat()
    }

    fn parse(bytes: &[u8]) -> SMBParseResult<&[u8], Self> {
        let (remaining, header) = S::smb_from_bytes(bytes)?;
        trace!(?header, remaining_len = remaining.len(), "parsed message header");
        let discriminator_code = (header.command_code().into()) | ((header.sender() as u64) << 16);
        let (remaining, body) = T::smb_enum_from_bytes(remaining, discriminator_code)?;
        Ok((remaining, Self { header, body }))
    }

    fn signature(&self, nonce: &[u8], key: &[u8], algorithm: SigningAlgorithm) -> SMBResult<Vec<u8>> {
        let res = match algorithm {
            SigningAlgorithm::HmacSha256 => {
                let mut hmac = Hmac::<Sha256>::new_from_slice(key)
                    .map_err(SMBError::crypto_error)?;
                hmac.update(&self.as_bytes());
                hmac.finalize()
                    .into_bytes()
                    .to_vec()
            }
            SigningAlgorithm::AesCmac => {
                let mut cmac = Cmac::<Aes128>::new_from_slice(key)
                    .map_err(SMBError::crypto_error)?;
                cmac.update(&self.as_bytes());
                cmac.finalize()
                    .into_bytes()
                    .to_vec()
            }
            SigningAlgorithm::AesGmac => {
                todo!();
                // let key = Key::<Aes128Gcm>::from_slice(key);
                // let cipher = Aes128Gcm::new(&key);
                // let nonce = Nonce::from_slice(nonce);
                // cipher.encrypt(&nonce, &self.as_bytes())?
                //     .to_vec()
            }
        };
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::body::empty::SMBEmpty;
    use crate::protocol::header::command_code::SMBCommandCode;
    use crate::protocol::header::flags::SMBFlags;

    fn echo_request_message() -> SMBSyncMessage {
        let header = SMBSyncHeader::new(
            SMBCommandCode::Echo,
            SMBFlags::empty(),
            0, 1, 0, 0, [0; 16],
        );
        let body = SMBBody::EchoRequest(SMBEmpty);
        SMBMessage::new(header, body)
    }

    /// Wire format: [0..2] padding, [2..4] big-endian length, [4..] header+body.
    #[test]
    fn as_bytes_starts_with_netbios_header() {
        let msg = echo_request_message();
        let bytes = msg.as_bytes();
        assert_eq!(bytes[0], 0x00, "First padding byte");
        assert_eq!(bytes[1], 0x00, "Second padding byte");
        // Length is big-endian u16 of (64-byte header + 4-byte echo body = 68)
        let len = u16::from_be_bytes([bytes[2], bytes[3]]);
        assert_eq!(len, 68, "NetBIOS length should be header(64) + body(4)");
    }

    /// Total wire size = 4 (NetBIOS) + 64 (header) + 4 (echo body) = 72
    #[test]
    fn as_bytes_total_length() {
        let msg = echo_request_message();
        let bytes = msg.as_bytes();
        assert_eq!(bytes.len(), 72);
    }

    /// The SMB2 header starts at offset 4 in the wire format.
    #[test]
    fn as_bytes_contains_protocol_id() {
        let msg = echo_request_message();
        let bytes = msg.as_bytes();
        assert_eq!(bytes[4], 0xFE);
        assert_eq!(bytes[5], b'S');
        assert_eq!(bytes[6], b'M');
        assert_eq!(bytes[7], b'B');
    }

    /// Round-trip: as_bytes then parse (skipping the 4-byte NetBIOS header).
    #[test]
    fn echo_message_round_trip() {
        let msg = echo_request_message();
        let bytes = msg.as_bytes();
        let (_, parsed) = SMBSyncMessage::parse(&bytes[4..]).unwrap();
        assert_eq!(parsed.header.command, SMBCommandCode::Echo);
        assert_eq!(parsed.header.message_id, 1);
        assert_eq!(parsed.body, SMBBody::EchoRequest(SMBEmpty));
    }

    /// HmacSha256 signature should produce a non-empty result.
    #[test]
    fn hmac_sha256_signature_is_nonempty() {
        let msg = echo_request_message();
        let key = [0xAB; 16];
        let sig = msg.signature(&[], &key, SigningAlgorithm::HmacSha256).unwrap();
        assert!(!sig.is_empty(), "HMAC-SHA256 signature should not be empty");
        assert_eq!(sig.len(), 32, "HMAC-SHA256 produces 32 bytes");
    }

    /// AesCmac signature should produce a 16-byte result.
    #[test]
    fn aes_cmac_signature_is_16_bytes() {
        let msg = echo_request_message();
        let key = [0xCD; 16];
        let sig = msg.signature(&[], &key, SigningAlgorithm::AesCmac).unwrap();
        assert_eq!(sig.len(), 16, "AES-CMAC produces 16 bytes");
    }
}