use std::marker::PhantomData;

use bitflags::bitflags;
use nom::bytes::complete::take;
use nom::combinator::{map, map_res};
use nom::Err::Error;
use nom::error::ErrorKind;
use nom::IResult;
use nom::multi::count;
use nom::number::complete::{le_u16, le_u32};
use nom::sequence::tuple;
use num_enum::TryFromPrimitive;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use smb_core::{SMBByteSize, SMBFromBytes, SMBResult, SMBToBytes};
use smb_core::error::SMBError;
use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::byte_helper::{u16_to_bytes, u32_to_bytes};
use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

const PRE_AUTH_INTEGRITY_CAPABILITIES_TAG: u16 = 0x01;
const ENCRYPTION_CAPABILITIES_TAG: u16 = 0x02;
const COMPRESSION_CAPABILITIES_TAG: u16 = 0x03;
const NETNAME_NEGOTIATE_CONTEXT_ID_TAG: u16 = 0x05;
const TRANSPORT_CAPABILITIES_TAG: u16 = 0x06;
const RDMA_TRANSFORM_CAPABILITIES_TAG: u16 = 0x07;
const SIGNING_CAPABILITIES_TAG: u16 = 0x08;

macro_rules! ctx_to_bytes {
    ($body: expr) => {{
        let bytes = $body.as_bytes();
        [
            &u16_to_bytes($body.byte_code())[0..],
            &u16_to_bytes(bytes.len() as u16),
            &[0; 4],
            &*bytes,
        ]
        .concat()
    }};
}

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

macro_rules! ctx_parse_enumify {
    ($enumType: expr, $bodyType: expr, $data: expr, $len: expr) => {{
        let (_, body) = $bodyType($data)?;
        let padding = if $len % 8 == 0 || (6 + $len) as usize >= $data.len() {
            0
        } else {
            8 - $len % 8
        };
        let (remaining, _) = take(6 + $len + padding)($data)?;
        Ok((remaining, $enumType(body)))
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
            return Err(SMBError::ParseError("Invalid padding block"));
        }
        let remaining = &$data[remove_size..];
        Ok((remaining, $enumType(body)))
    }};
}

macro_rules! vector_with_only_last {
    ($vector: expr) => {{
        $vector.sort();
        vec![*$vector.last()?]
    }};
}

macro_rules! enum_iter_to_bytes {
    ($iter: expr) => {{
        $iter
            .flat_map(|item| u16_to_bytes(*item as u16))
            .collect::<Vec<u8>>()
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
}

impl SMBByteSize for NegotiateContext {
    fn smb_byte_size(&self) -> usize {
        let ctx_size = match self {
            NegotiateContext::PreAuthIntegrityCapabilities(x) => x.smb_byte_size(),
            NegotiateContext::EncryptionCapabilities(x) => x.smb_byte_size(),
            NegotiateContext::CompressionCapabilities(x) => x.smb_byte_size(),
            NegotiateContext::NetnameNegotiateContextID(x) => x.smb_byte_size(),
            NegotiateContext::TransportCapabilities(x) => x.smb_byte_size(),
            NegotiateContext::RDMATransformCapabilities(x) => x.smb_byte_size(),
            NegotiateContext::SigningCapabilities(x) => x.smb_byte_size(),
        } + 2;
        ctx_size
        // if ctx_size % 8 == 0 {
        //     ctx_size
        // } else {
        //     ctx_size + (8 - (ctx_size % 8))
        // }
    }
}

impl SMBFromBytes for NegotiateContext {
    fn smb_from_bytes(input: &[u8]) -> SMBResult<&[u8], Self> where Self: Sized {
        if input.len() < 4 { return Err(SMBError::ParseError("Input too small")) }
        let (remaining, ctx_type) = u16::smb_from_bytes(input)?;
        let (_, ctx_len) = u16::smb_from_bytes(remaining)?;

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
            _ => Err(SMBError::ParseError("Invalid negotiate context type"))
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
        }
    }
}

impl NegotiateContext {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (_, (ctx_type_num, ctx_len, _)) = tuple((le_u16, le_u16, take(4_usize)))(bytes)?;
        let (remaining, _) = take(2_usize)(bytes)?;
        match ctx_type_num {
            0x01 => ctx_parse_enumify!(
                Self::PreAuthIntegrityCapabilities,
                PreAuthIntegrityCapabilities::parse,
                remaining,
                ctx_len
            ),
            0x02 => ctx_parse_enumify!(
                Self::EncryptionCapabilities,
                EncryptionCapabilities::parse,
                remaining,
                ctx_len
            ),
            0x03 => ctx_parse_enumify!(
                Self::CompressionCapabilities,
                CompressionCapabilities::parse,
                remaining,
                ctx_len
            ),
            0x05 => ctx_parse_enumify!(
                Self::NetnameNegotiateContextID,
                NetnameNegotiateContextID::parse,
                remaining,
                ctx_len
            ),
            0x06 => ctx_parse_enumify!(
                Self::TransportCapabilities,
                TransportCapabilities::parse,
                remaining,
                ctx_len
            ),
            0x07 => ctx_parse_enumify!(
                Self::RDMATransformCapabilities,
                RDMATransformCapabilities::parse,
                remaining,
                ctx_len
            ),
            0x08 => ctx_parse_enumify!(
                Self::SigningCapabilities,
                SigningCapabilities::parse,
                remaining,
                ctx_len
            ),
            _ => Err(Error(nom::error::Error::new(remaining, ErrorKind::Fail))),
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            NegotiateContext::PreAuthIntegrityCapabilities(body) => ctx_to_bytes!(body),
            NegotiateContext::EncryptionCapabilities(body) => ctx_to_bytes!(body),
            NegotiateContext::CompressionCapabilities(body) => ctx_to_bytes!(body),
            NegotiateContext::NetnameNegotiateContextID(body) => ctx_to_bytes!(body),
            NegotiateContext::TransportCapabilities(body) => ctx_to_bytes!(body),
            NegotiateContext::RDMATransformCapabilities(body) => ctx_to_bytes!(body),
            NegotiateContext::SigningCapabilities(body) => ctx_to_bytes!(body),
        }
    }

    pub fn response_from_existing(&self) -> Option<Self> {
        match self {
            NegotiateContext::PreAuthIntegrityCapabilities(body) => {
                let hash_algorithms = vector_with_only_last!(body.hash_algorithms.clone());
                let mut salt = vec![0_u8; 32];
                rand::rngs::ThreadRng::default().fill_bytes(&mut salt);
                Some(NegotiateContext::PreAuthIntegrityCapabilities(
                    PreAuthIntegrityCapabilities {
                        hash_algorithms,
                        salt,
                        reserved: PhantomData
                    },
                ))
            }
            NegotiateContext::EncryptionCapabilities(body) => {
                let ciphers = vector_with_only_last!(body.ciphers.clone());
                Some(NegotiateContext::EncryptionCapabilities(
                    EncryptionCapabilities { reserved: PhantomData, ciphers },
                ))
            }
            NegotiateContext::CompressionCapabilities(body) => {
                let compression_algorithms =
                    vector_with_only_last!(body.compression_algorithms.clone());
                Some(NegotiateContext::CompressionCapabilities(
                    CompressionCapabilities {
                        compression_algorithms,
                        flags: body.flags,
                    },
                ))
            }
            NegotiateContext::NetnameNegotiateContextID(_) => Some(
                NegotiateContext::NetnameNegotiateContextID(NetnameNegotiateContextID {
                    reserved: PhantomData,
                    netname: "fakeserver".into(),
                }),
            ),
            NegotiateContext::TransportCapabilities(_) => Some(
                NegotiateContext::TransportCapabilities(TransportCapabilities {
                    flags: TransportCapabilitiesFlags::empty(),
                }),
            ),
            NegotiateContext::RDMATransformCapabilities(_) => Some(
                NegotiateContext::RDMATransformCapabilities(RDMATransformCapabilities {
                    reserved: PhantomData,
                    transform_ids: vec![RDMATransformID::None],
                }),
            ),
            NegotiateContext::SigningCapabilities(body) => {
                let signing_algorithms = vector_with_only_last!(body.signing_algorithms.clone());
                Some(NegotiateContext::SigningCapabilities(
                    SigningCapabilities { reserved: PhantomData, signing_algorithms },
                ))
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct PreAuthIntegrityCapabilities {
    #[smb_skip(start = 0, length = 10)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_vector(order = 1, count(start = 6, num_type = "u16"))]
    pub(crate) hash_algorithms: Vec<HashAlgorithm>,
    #[smb_vector(order = 2, count(start = 8, num_type = "u16"))]
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
        0x01
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (remaining, (_, alg_cnt, salt_len)) = tuple((take(6_usize), le_u16, le_u16))(bytes)?;
        let (remaining, hash_algorithms) =
            count(map_res(le_u16, HashAlgorithm::try_from), alg_cnt as usize)(remaining)?;
        let (remaining, salt) = map(take(salt_len), |s: &[u8]| s.to_vec())(remaining)?;
        Ok((
            remaining,
            Self {
                hash_algorithms,
                salt,
                reserved: PhantomData
            },
        ))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        [
            &u16_to_bytes(self.hash_algorithms.len() as u16),
            &u16_to_bytes(self.salt.len() as u16),
            &*enum_iter_to_bytes!(self.hash_algorithms.iter()),
            &*self.salt,
        ]
        .concat()
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct EncryptionCapabilities {
    #[smb_skip(start = 0, length = 8)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_vector(order = 1, count(start = 6, num_type = "u16"))]
    pub(crate) ciphers: Vec<EncryptionCipher>,
}

#[repr(u16)]
#[derive(
Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Clone, Ord, PartialOrd, Copy, SMBFromBytes, SMBByteSize, SMBToBytes
)]
pub enum EncryptionCipher {
    AES128GCM = 0x01,
    AES128CCM,
    AES256GCM,
    AES256CCM,
}

impl EncryptionCapabilities {
    fn byte_code(&self) -> u16 {
        0x02
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (remaining, _) = take(6_usize)(bytes)?;
        let (remaining, cipher_cnt) = le_u16(remaining)?;
        let (remaining, ciphers) = count(
            map_res(le_u16, EncryptionCipher::try_from),
            cipher_cnt as usize,
        )(remaining)?;
        Ok((remaining, Self { reserved: PhantomData, ciphers }))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        [
            &u16_to_bytes(self.ciphers.len() as u16)[0..],
            &*enum_iter_to_bytes!(self.ciphers.iter()),
        ]
        .concat()
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct CompressionCapabilities {
    #[smb_direct(start = 10)]
    pub(crate) flags: CompressionCapabilitiesFlags,
    #[smb_vector(order = 1, count(start = 6, num_type = "u16"))]
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
        0x03
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (remaining, (_, alg_cnt, _, flags)) = tuple((
            take(6_usize),
            le_u16,
            le_u16,
            map_res(le_u32, CompressionCapabilitiesFlags::try_from),
        ))(bytes)?;
        let (remaining, compression_algorithms) = count(
            map_res(le_u16, CompressionAlgorithm::try_from),
            alg_cnt as usize,
        )(remaining)?;
        Ok((
            remaining,
            Self {
                flags,
                compression_algorithms,
            },
        ))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        [
            &u16_to_bytes(self.compression_algorithms.len() as u16)[0..],
            &[0, 0],
            &u32_to_bytes(self.flags as u32),
            &*enum_iter_to_bytes!(self.compression_algorithms.iter()),
        ]
        .concat()
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct NetnameNegotiateContextID {
    #[smb_skip(start = 0, length = 6)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_vector(order = 1, count(start = 0, num_type = "u16"))]
    pub(crate) netname: Vec<u8>,
}

impl NetnameNegotiateContextID {
    fn byte_code(&self) -> u16 {
        0x05
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (remaining, name_len) = le_u16(bytes)?;
        let (remaining, _) = take(4_usize)(remaining)?;
        let (remaining, netname) = take(name_len)(remaining)?;
        Ok((remaining, Self { reserved: PhantomData, netname: netname.to_vec() }))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.netname.clone()
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
        0x06
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (remaining, flags) =
            map(le_u32, TransportCapabilitiesFlags::from_bits_truncate)(bytes)?;
        Ok((remaining, Self { flags }))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        u32_to_bytes(self.flags.bits()).into()
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct RDMATransformCapabilities {
    #[smb_skip(start = 0, length = 14)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_vector(order = 1, count(start = 6, num_type = "u16"))]
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
        0x07
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (remaining, transform_cnt) = le_u16(bytes)?;
        let (remaining, transform_ids) = count(
            map_res(le_u16, RDMATransformID::try_from),
            transform_cnt as usize,
        )(remaining)?;
        Ok((remaining, Self { reserved: PhantomData, transform_ids }))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        [
            &u16_to_bytes(self.transform_ids.len() as u16)[0..],
            &[0; 6],
            &*enum_iter_to_bytes!(self.transform_ids.iter()),
        ]
        .concat()
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct SigningCapabilities {
    #[smb_skip(start = 0, length = 8)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_vector(order = 1, count(start = 6, num_type = "u16"))]
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
        0x08
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (remaining, signing_alg_cnt) = le_u16(bytes)?;
        let (remaining, signing_algorithms) = count(
            map_res(le_u16, SigningAlgorithm::try_from),
            signing_alg_cnt as usize,
        )(remaining)?;
        Ok((remaining, Self { reserved: PhantomData, signing_algorithms }))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        [
            &u16_to_bytes(self.signing_algorithms.len() as u16)[0..],
            &*enum_iter_to_bytes!(self.signing_algorithms.iter()),
        ]
        .concat()
    }
}

