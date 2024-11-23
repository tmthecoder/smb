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

use crate::byte_helper::u16_to_bytes;
use crate::protocol::body::{Body, LegacySMBBody, SMBBody};
use crate::protocol::body::negotiate::context::SigningAlgorithm;
use crate::protocol::header::{Header, LegacySMBHeader, SMBSyncHeader};

pub type SMBSyncMessage = SMBMessage<SMBSyncHeader, SMBBody>;
pub type SMBLegacyMessage = SMBMessage<LegacySMBHeader, LegacySMBBody>;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct SMBMessage<S: Header, T: Body<S>> {
    pub header: S,
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

pub trait Message {
    fn as_bytes(&self) -> Vec<u8>;
    fn parse(bytes: &[u8]) -> SMBParseResult<&[u8], Self> where Self: Sized;

    fn signature(&self, nonce: &[u8], key: &[u8], algorithm: SigningAlgorithm) -> SMBResult<Vec<u8>>;
}

impl SMBMessage<SMBSyncHeader, SMBBody> {
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
        println!("header: {:?}", header);
        println!("remaining: {:?}", remaining);
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