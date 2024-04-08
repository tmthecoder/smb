use std::collections::HashSet;
use std::marker::PhantomData;

use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use smb_core::{SMBByteSize, SMBFromBytes, SMBParseResult, SMBResult, SMBToBytes};
use smb_core::error::SMBError;
use smb_core::nt_status::NTStatus;
use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::byte_helper::u16_to_bytes;
use crate::server::connection::{Connection, SMBConnection, SMBConnectionUpdate};
use crate::server::Server;
use crate::socket::message_stream::{SMBReadStream, SMBWriteStream};
use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

const PRE_AUTH_INTEGRITY_CAPABILITIES_TAG: u16 = 0x01;
const ENCRYPTION_CAPABILITIES_TAG: u16 = 0x02;
const COMPRESSION_CAPABILITIES_TAG: u16 = 0x03;
const NETNAME_NEGOTIATE_CONTEXT_ID_TAG: u16 = 0x05;
const TRANSPORT_CAPABILITIES_TAG: u16 = 0x06;
const RDMA_TRANSFORM_CAPABILITIES_TAG: u16 = 0x07;
const SIGNING_CAPABILITIES_TAG: u16 = 0x08;
const POSIX_EXTENSIONS_TAG: u16 = 0x0100;

macro_rules! ctx_smb_to_bytes {
    ($body: expr) => {{
        let mut bytes = $body.smb_to_bytes();
        let size = bytes.len() as u16 - 6;
        bytes[0..2].copy_from_slice(&size.smb_to_bytes());
        [
            &u16_to_bytes($body.byte_code())[0..],
            &size.smb_to_bytes(),
            &bytes[2..],
        ]
        .concat()
    }};
}

macro_rules! ctx_smb_from_bytes_enumify {
    ($enumType: expr, $bodyType: expr, $data: expr, $len: expr) => {{
        let (_, body) = $bodyType($data)?;
        let padding = if $len % 8 == 0 || (6 + $len) as usize >= $data.len() {
            0
        } else {
            8 - $len % 8
        };
        let remove_size = (6 + $len + padding) as usize;
        if remove_size > $data.len() {
            return Err(SMBError::parse_error("Invalid padding block"));
        }
        let remaining = &$data[remove_size..];
        Ok((remaining, $enumType(body)))
    }};
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NegotiateContext {
    PreAuthIntegrityCapabilities(PreAuthIntegrityCapabilities),
    EncryptionCapabilities(EncryptionCapabilities),
    CompressionCapabilities(CompressionCapabilities),
    NetnameNegotiateContextID(NetnameNegotiateContextID),
    TransportCapabilities(TransportCapabilities),
    RDMATransformCapabilities(RDMATransformCapabilities),
    SigningCapabilities(SigningCapabilities),
    PosixExtensions(PosixExtensions)
}

impl SMBByteSize for NegotiateContext {
    fn smb_byte_size(&self) -> usize {
        (match self {
            NegotiateContext::PreAuthIntegrityCapabilities(x) => x.smb_byte_size(),
            NegotiateContext::EncryptionCapabilities(x) => x.smb_byte_size(),
            NegotiateContext::CompressionCapabilities(x) => x.smb_byte_size(),
            NegotiateContext::NetnameNegotiateContextID(x) => x.smb_byte_size(),
            NegotiateContext::TransportCapabilities(x) => x.smb_byte_size(),
            NegotiateContext::RDMATransformCapabilities(x) => x.smb_byte_size(),
            NegotiateContext::SigningCapabilities(x) => x.smb_byte_size(),
            NegotiateContext::PosixExtensions(x) => x.smb_byte_size()
        }) + 2
    }
}

impl SMBFromBytes for NegotiateContext {
    fn smb_from_bytes(input: &[u8]) -> SMBParseResult<&[u8], Self> where Self: Sized {
        if input.len() < 4 { return Err(SMBError::parse_error("Input too small")) }
        let (remaining, ctx_type) = u16::smb_from_bytes(input)?;
        let (_, ctx_len) = u16::smb_from_bytes(remaining)?;

        println!("type {:?}, len {}", ctx_type, ctx_len);
        
        match ctx_type {
            PRE_AUTH_INTEGRITY_CAPABILITIES_TAG => ctx_smb_from_bytes_enumify!(
                Self::PreAuthIntegrityCapabilities,
                PreAuthIntegrityCapabilities::smb_from_bytes,
                remaining,
                ctx_len
            ),
            ENCRYPTION_CAPABILITIES_TAG => ctx_smb_from_bytes_enumify!(
                Self::EncryptionCapabilities,
                EncryptionCapabilities::smb_from_bytes,
                remaining,
                ctx_len
            ),
            COMPRESSION_CAPABILITIES_TAG => ctx_smb_from_bytes_enumify!(
                Self::CompressionCapabilities,
                CompressionCapabilities::smb_from_bytes,
                remaining,
                ctx_len
            ),
            NETNAME_NEGOTIATE_CONTEXT_ID_TAG => ctx_smb_from_bytes_enumify!(
                Self::NetnameNegotiateContextID,
                NetnameNegotiateContextID::smb_from_bytes,
                remaining,
                ctx_len
            ),
            TRANSPORT_CAPABILITIES_TAG => ctx_smb_from_bytes_enumify!(
                Self::TransportCapabilities,
                TransportCapabilities::smb_from_bytes,
                remaining,
                ctx_len
            ),
            RDMA_TRANSFORM_CAPABILITIES_TAG => ctx_smb_from_bytes_enumify!(
                Self::RDMATransformCapabilities,
                RDMATransformCapabilities::smb_from_bytes,
                remaining,
                ctx_len
            ),
            SIGNING_CAPABILITIES_TAG => ctx_smb_from_bytes_enumify!(
                Self::SigningCapabilities,
                SigningCapabilities::smb_from_bytes,
                remaining,
                ctx_len
            ),
            POSIX_EXTENSIONS_TAG => ctx_smb_from_bytes_enumify!(
                Self::PosixExtensions,
                PosixExtensions::smb_from_bytes,
                remaining,
                ctx_len
            ),
            _ => Err(SMBError::parse_error("Invalid negotiate context type"))
        }
    }
}

impl SMBToBytes for NegotiateContext {
    fn smb_to_bytes(&self) -> Vec<u8> {
        match self {
            NegotiateContext::PreAuthIntegrityCapabilities(body) => ctx_smb_to_bytes!(body),
            NegotiateContext::EncryptionCapabilities(body) => ctx_smb_to_bytes!(body),
            NegotiateContext::CompressionCapabilities(body) => ctx_smb_to_bytes!(body),
            NegotiateContext::NetnameNegotiateContextID(body) => ctx_smb_to_bytes!(body),
            NegotiateContext::TransportCapabilities(body) => ctx_smb_to_bytes!(body),
            NegotiateContext::RDMATransformCapabilities(body) => ctx_smb_to_bytes!(body),
            NegotiateContext::SigningCapabilities(body) => ctx_smb_to_bytes!(body),
            NegotiateContext::PosixExtensions(body) => ctx_smb_to_bytes!(body),
        }
    }
}

impl NegotiateContext {
    pub fn byte_code(&self) -> u16 {
        match self {
            NegotiateContext::PreAuthIntegrityCapabilities(x) => x.byte_code(),
            NegotiateContext::EncryptionCapabilities(x) => x.byte_code(),
            NegotiateContext::CompressionCapabilities(x) => x.byte_code(),
            NegotiateContext::NetnameNegotiateContextID(x) => x.byte_code(),
            NegotiateContext::TransportCapabilities(x) => x.byte_code(),
            NegotiateContext::RDMATransformCapabilities(x) => x.byte_code(),
            NegotiateContext::SigningCapabilities(x) => x.byte_code(),
            NegotiateContext::PosixExtensions(x) => x.byte_code(),
        }
    }
    pub fn from_connection_state<R: SMBReadStream, W: SMBWriteStream, S: Server>(connection: &SMBConnection<R, W, S>, request_contexts: HashSet<u16>) -> Vec<Self> {
        let mut response_contexts = Vec::new();
        if request_contexts.contains(&PRE_AUTH_INTEGRITY_CAPABILITIES_TAG) {
            response_contexts.push(Self::PreAuthIntegrityCapabilities(PreAuthIntegrityCapabilities::from_connection_state(connection)));
        }
        if request_contexts.contains(&ENCRYPTION_CAPABILITIES_TAG) {
            response_contexts.push(Self::EncryptionCapabilities(EncryptionCapabilities::from_connection_state(connection)));
        }
        if request_contexts.contains(&COMPRESSION_CAPABILITIES_TAG) {
            response_contexts.push(Self::CompressionCapabilities(CompressionCapabilities::from_connection_state(connection)));
        }
        if request_contexts.contains(&RDMA_TRANSFORM_CAPABILITIES_TAG) {
            response_contexts.push(Self::RDMATransformCapabilities(RDMATransformCapabilities::from_connection_state(connection)));
        }
        if request_contexts.contains(&SIGNING_CAPABILITIES_TAG) {
            response_contexts.push(Self::SigningCapabilities(SigningCapabilities::from_connection_state(connection)));
        }
        if request_contexts.contains(&TRANSPORT_CAPABILITIES_TAG) {
            response_contexts.push(Self::TransportCapabilities(TransportCapabilities::from_connection_state(connection)));
        }
        if request_contexts.contains(&POSIX_EXTENSIONS_TAG) {
            response_contexts.push(Self::PosixExtensions(PosixExtensions::from_connection_state(connection)));
        }
        response_contexts
    }

    pub fn validate_and_set_state<R: SMBReadStream, W: SMBWriteStream, S: Server>(&self, connection: SMBConnectionUpdate<R, W, S>, server: &S) -> SMBResult<(SMBConnectionUpdate<R, W, S>, bool)> {
        match self {
            NegotiateContext::PreAuthIntegrityCapabilities(x) => x.validate_and_set_state(connection),
            NegotiateContext::EncryptionCapabilities(x) => x.validate_and_set_state(connection),
            NegotiateContext::CompressionCapabilities(x) => x.validate_and_set_state(connection, server),
            NegotiateContext::NetnameNegotiateContextID(x) => Ok((connection, false)),
            NegotiateContext::TransportCapabilities(x) => x.validate_and_set_state(connection),
            NegotiateContext::RDMATransformCapabilities(x) => x.validate_and_set_state(connection, server),
            NegotiateContext::SigningCapabilities(x) => x.validate_and_set_state(connection),
            NegotiateContext::PosixExtensions(x) => x.validate_and_set_state(connection),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct PreAuthIntegrityCapabilities {
    #[smb_skip(start = 0, length = 10)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_vector(order = 1, count(inner(start = 6, num_type = "u16")))]
    pub(crate) hash_algorithms: Vec<HashAlgorithm>,
    #[smb_vector(order = 2, count(inner(start = 8, num_type = "u16")))]
    pub(crate) salt: Vec<u8>,
}

#[repr(u16)]
#[derive(
Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Copy, Clone, Ord, PartialOrd, SMBFromBytes, SMBByteSize, SMBToBytes
)]
pub enum HashAlgorithm {
    SHA512 = 0x01,
}

impl PreAuthIntegrityCapabilities {
    fn byte_code(&self) -> u16 {
        PRE_AUTH_INTEGRITY_CAPABILITIES_TAG
    }

    fn from_connection_state<R: SMBReadStream, W: SMBWriteStream, S: Server>(connection: &SMBConnection<R, W, S>) -> Self {
        let mut salt = vec![0_u8; 32];
        rand::rngs::ThreadRng::default().fill_bytes(&mut salt);
        Self {
            reserved: Default::default(),
            hash_algorithms: vec![connection.preauth_integrity_hash_id()],
            salt,
        }
    }

    pub fn validate_and_set_state<R: SMBReadStream, W: SMBWriteStream, S: Server>(&self, connection: SMBConnectionUpdate<R, W, S>) -> SMBResult<(SMBConnectionUpdate<R, W, S>, bool)> {
        if let Some(algorithm) = self.hash_algorithms.first() {
            Ok((connection
                    .preauth_integrity_hash_id(*algorithm)
                    .preauth_integrity_hash_value(Vec::new()), true))
        } else {
            Err(SMBError::response_error(NTStatus::InvalidParameter))
        }
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct EncryptionCapabilities {
    #[smb_skip(start = 0, length = 8)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_vector(order = 1, count(inner(start = 6, num_type = "u16")))]
    pub(crate) ciphers: Vec<EncryptionCipher>,
}

#[repr(u16)]
#[derive(
Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Clone, Ord, PartialOrd, Copy, SMBFromBytes, SMBByteSize, SMBToBytes
)]
pub enum EncryptionCipher {
    None = 0x0,
    AES128GCM = 0x01,
    AES128CCM,
    AES256GCM,
    AES256CCM,
}

impl EncryptionCapabilities {
    fn byte_code(&self) -> u16 {
        ENCRYPTION_CAPABILITIES_TAG
    }

    fn from_connection_state<R: SMBReadStream, W: SMBWriteStream, S: Server>(connection: &SMBConnection<R, W, S>) -> Self {
        Self {
            reserved: Default::default(),
            ciphers: vec![connection.cipher_id()],
        }
    }
    pub fn validate_and_set_state<R: SMBReadStream, W: SMBWriteStream, S: Server>(&self, connection: SMBConnectionUpdate<R, W, S>) -> SMBResult<(SMBConnectionUpdate<R, W, S>, bool)> {
        let mut ciphers = self.ciphers.clone();
        ciphers.sort();
        ciphers.reverse();
        if let Some(cipher) = ciphers.first() {
            Ok((connection.cipher_id(*cipher), true))
        } else {
            Ok((connection, true))
        }
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct CompressionCapabilities {
    #[smb_direct(start(fixed = 10))]
    pub(crate) flags: CompressionCapabilitiesFlags,
    #[smb_vector(order = 1, count(inner(start = 6, num_type = "u16")))]
    pub(crate) compression_algorithms: Vec<CompressionAlgorithm>,
}

#[repr(u32)]
#[derive(
Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Clone, Ord, PartialOrd, Copy, SMBFromBytes, SMBByteSize, SMBToBytes
)]
pub enum CompressionCapabilitiesFlags {
    None = 0x0,
    Chained,
}

#[repr(u16)]
#[derive(
Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Clone, Ord, PartialOrd, Copy, SMBFromBytes, SMBByteSize, SMBToBytes
)]
pub enum CompressionAlgorithm {
    None = 0x0,
    Lznt1,
    LZ77,
    Lz77AndHuffman,
    PatternV1,
}

impl CompressionCapabilities {
    fn byte_code(&self) -> u16 {
        COMPRESSION_CAPABILITIES_TAG
    }

    fn from_connection_state<R: SMBReadStream, W: SMBWriteStream, S: Server>(connection: &SMBConnection<R, W, S>) -> Self {
        let flags = if connection.supports_chained_compression() {
            CompressionCapabilitiesFlags::Chained
        } else {
            CompressionCapabilitiesFlags::None
        };
        Self {
            flags,
            compression_algorithms: connection.compression_ids().clone(),
        }
    }
    pub fn validate_and_set_state<R: SMBReadStream, W: SMBWriteStream, S: Server>(&self, connection: SMBConnectionUpdate<R, W, S>, server: &S) -> SMBResult<(SMBConnectionUpdate<R, W, S>, bool)> {
        if !server.compression_supported() {
            return Ok((connection, false))
        }
        if self.compression_algorithms.is_empty() {
            return Err(SMBError::response_error(NTStatus::InvalidParameter));
        }
        Ok((connection.compression_ids(self.compression_algorithms.clone()), true))
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct NetnameNegotiateContextID {
    #[smb_skip(start = 0, length = 6)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_string(order = 1, length(inner(start = 0, num_type = "u16")), underlying = "u16")]
    pub(crate) netname: String,
}

impl NetnameNegotiateContextID {
    fn byte_code(&self) -> u16 {
        NETNAME_NEGOTIATE_CONTEXT_ID_TAG
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct TransportCapabilities {
    #[smb_direct(start = 0, length = 4)]
    pub(crate) flags: TransportCapabilitiesFlags,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
    pub struct TransportCapabilitiesFlags: u32 {
        const ACCEPT_TRANSPORT_LEVEL_SECURITY = 0x01;
    }
}

impl_smb_byte_size_for_bitflag! {TransportCapabilitiesFlags}
impl_smb_from_bytes_for_bitflag! {TransportCapabilitiesFlags}
impl_smb_to_bytes_for_bitflag! {TransportCapabilitiesFlags}

impl TransportCapabilities {
    fn byte_code(&self) -> u16 {
        TRANSPORT_CAPABILITIES_TAG
    }

    fn from_connection_state<R: SMBReadStream, W: SMBWriteStream, S: Server>(connection: &SMBConnection<R, W, S>) -> Self {
        let flags = if connection.supports_chained_compression() {
            TransportCapabilitiesFlags::ACCEPT_TRANSPORT_LEVEL_SECURITY
        } else {
            TransportCapabilitiesFlags::empty()
        };
        Self {
            flags,
        }
    }
    pub fn validate_and_set_state<R: SMBReadStream, W: SMBWriteStream, S: Server>(&self, connection: SMBConnectionUpdate<R, W, S>) -> SMBResult<(SMBConnectionUpdate<R, W, S>, bool)> {
        if self.flags.contains(TransportCapabilitiesFlags::ACCEPT_TRANSPORT_LEVEL_SECURITY) {
            Ok((connection.accept_transport_security(true), true))
        } else {
            Ok((connection, true))
        }
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct RDMATransformCapabilities {
    #[smb_skip(start = 0, length = 14)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_vector(order = 1, count(inner(start = 6, num_type = "u16")))]
    pub(crate) transform_ids: Vec<RDMATransformID>,
}

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Clone, Copy, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub enum RDMATransformID {
    None = 0x0,
    Encryption,
    Signing,
}

impl RDMATransformCapabilities {
    fn byte_code(&self) -> u16 {
        RDMA_TRANSFORM_CAPABILITIES_TAG
    }
    fn from_connection_state<R: SMBReadStream, W: SMBWriteStream, S: Server>(connection: &SMBConnection<R, W, S>) -> Self {
        let transform_ids = if connection.rdma_transform_ids().is_empty() {
            vec![RDMATransformID::None]
        } else {
            connection.rdma_transform_ids().clone()
        };
        Self {
            reserved: Default::default(),
            transform_ids,
        }
    }
    pub fn validate_and_set_state<R: SMBReadStream, W: SMBWriteStream, S: Server>(&self, connection: SMBConnectionUpdate<R, W, S>, server: &S) -> SMBResult<(SMBConnectionUpdate<R, W, S>, bool)> {
        if !server.rdma_transform_supported() {
            return Ok((connection, false))
        }
        if self.transform_ids.is_empty() {
            return Err(SMBError::response_error(NTStatus::InvalidParameter));
        }
        Ok((connection.rdma_transform_ids(self.transform_ids.clone()), true))
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct SigningCapabilities {
    #[smb_skip(start = 0, length = 8)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_vector(order = 1, count(inner(start = 6, num_type = "u16")))]
    pub(crate) signing_algorithms: Vec<SigningAlgorithm>,
}

#[repr(u16)]
#[derive(
Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Clone, Ord, PartialOrd, Copy, SMBFromBytes, SMBByteSize, SMBToBytes
)]
pub enum SigningAlgorithm {
    HmacSha256 = 0x0,
    AesCmac,
    AesGmac,
}

impl SigningCapabilities {
    fn byte_code(&self) -> u16 {
        SIGNING_CAPABILITIES_TAG
    }

    fn from_connection_state<R: SMBReadStream, W: SMBWriteStream, S: Server>(connection: &SMBConnection<R, W, S>) -> Self {
        Self {
            reserved: PhantomData,
            signing_algorithms: vec![connection.signing_algorithm_id()],
        }
    }
    pub fn validate_and_set_state<R: SMBReadStream, W: SMBWriteStream, S: Server>(&self, connection: SMBConnectionUpdate<R, W, S>) -> SMBResult<(SMBConnectionUpdate<R, W, S>, bool)> {
        if self.signing_algorithms.is_empty() {
            return Err(SMBError::response_error(NTStatus::InvalidParameter));
        }
        let mut algorithms = self.signing_algorithms.clone();
        algorithms.sort();
        Ok((connection.signing_algorithm_id(*algorithms.first().unwrap()), true))
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBToBytes, SMBByteSize)]
struct PosixExtensions {
    #[smb_skip(start = 0, length = 6)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_vector(order = 1, count(inner(start = 0, num_type = "u16")))]
    posix_reserved: Vec<u8>,
}

impl PosixExtensions {
    fn byte_code(&self) -> u16 { POSIX_EXTENSIONS_TAG }

    pub fn validate_and_set_state<R: SMBReadStream, W: SMBWriteStream, S: Server>(&self, connection: SMBConnectionUpdate<R, W, S>) -> SMBResult<(SMBConnectionUpdate<R, W, S>, bool)> {
        if self.posix_reserved.is_empty() {
            return Err(SMBError::response_error(NTStatus::InvalidParameter));
        }
        let connection = connection.posix_extension_payload(self.posix_reserved.clone());
        Ok((connection, true))
    }
    fn from_connection_state<R: SMBReadStream, W: SMBWriteStream, S: Server>(connection: &SMBConnection<R, W, S>) -> Self {
        Self {
            reserved: PhantomData,
            posix_reserved: connection.posix_extension_payload().to_vec(),
        }
    }
}