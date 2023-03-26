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

use smb_core::{SMBFromBytes, SMBResult};
use smb_core::error::SMBError;
use smb_derive::SMBFromBytes;

use crate::byte_helper::{u16_to_bytes, u32_to_bytes};
use crate::util::flags_helper::impl_smb_from_bytes;

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

macro_rules! ctx_parse_enumify {
    ($enumType: expr, $bodyType: expr, $data: expr, $len: expr) => {{
        let (_, body) = $bodyType($data).unwrap();
        let padding = if $len % 8 == 0 || (6 + $len) as usize >= $data.len() {
            0
        } else {
            8 - $len % 8
        };
        let (remaining, _) = take(6 + $len + padding)($data)?;
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
    PreAuthIntegrityCapabilities(PreAuthIntegrityCapabilitiesBody),
    EncryptionCapabilities(EncryptionCapabilitiesBody),
    CompressionCapabilities(CompressionCapabilitiesBody),
    NetnameNegotiateContextID(NetnameNegotiateContextIDBody),
    TransportCapabilities(TransportCapabilitiesBody),
    RDMATransformCapabilities(RDMATransformCapabilitiesBody),
    SigningCapabilities(SigningCapabilitiesBody),
}

impl NegotiateContext {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (_, (ctx_type_num, ctx_len, _)) = tuple((le_u16, le_u16, take(4_usize)))(bytes)?;
        let (remaining, _) = take(2_usize)(bytes)?;
        match ctx_type_num {
            0x01 => ctx_parse_enumify!(
                Self::PreAuthIntegrityCapabilities,
                PreAuthIntegrityCapabilitiesBody::parse,
                remaining,
                ctx_len
            ),
            0x02 => ctx_parse_enumify!(
                Self::EncryptionCapabilities,
                EncryptionCapabilitiesBody::parse,
                remaining,
                ctx_len
            ),
            0x03 => ctx_parse_enumify!(
                Self::CompressionCapabilities,
                CompressionCapabilitiesBody::parse,
                remaining,
                ctx_len
            ),
            0x05 => ctx_parse_enumify!(
                Self::NetnameNegotiateContextID,
                NetnameNegotiateContextIDBody::parse,
                remaining,
                ctx_len
            ),
            0x06 => ctx_parse_enumify!(
                Self::TransportCapabilities,
                TransportCapabilitiesBody::parse,
                remaining,
                ctx_len
            ),
            0x07 => ctx_parse_enumify!(
                Self::RDMATransformCapabilities,
                RDMATransformCapabilitiesBody::parse,
                remaining,
                ctx_len
            ),
            0x08 => ctx_parse_enumify!(
                Self::SigningCapabilities,
                SigningCapabilitiesBody::parse,
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
                    PreAuthIntegrityCapabilitiesBody {
                        hash_algorithms,
                        salt,
                    },
                ))
            }
            NegotiateContext::EncryptionCapabilities(body) => {
                let ciphers = vector_with_only_last!(body.ciphers.clone());
                Some(NegotiateContext::EncryptionCapabilities(
                    EncryptionCapabilitiesBody { ciphers },
                ))
            }
            NegotiateContext::CompressionCapabilities(body) => {
                let compression_algorithms =
                    vector_with_only_last!(body.compression_algorithms.clone());
                Some(NegotiateContext::CompressionCapabilities(
                    CompressionCapabilitiesBody {
                        compression_algorithms,
                        flags: body.flags,
                    },
                ))
            }
            NegotiateContext::NetnameNegotiateContextID(_) => Some(
                NegotiateContext::NetnameNegotiateContextID(NetnameNegotiateContextIDBody {
                    netname: "fakeserver".into(),
                }),
            ),
            NegotiateContext::TransportCapabilities(_) => Some(
                NegotiateContext::TransportCapabilities(TransportCapabilitiesBody {
                    flags: TransportCapabilitiesFlags::empty(),
                }),
            ),
            NegotiateContext::RDMATransformCapabilities(_) => Some(
                NegotiateContext::RDMATransformCapabilities(RDMATransformCapabilitiesBody {
                    transform_ids: vec![RDMATransformID::None],
                }),
            ),
            NegotiateContext::SigningCapabilities(body) => {
                let signing_algorithms = vector_with_only_last!(body.signing_algorithms.clone());
                Some(NegotiateContext::SigningCapabilities(
                    SigningCapabilitiesBody { signing_algorithms },
                ))
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct PreAuthIntegrityCapabilitiesBody {
    pub(crate) hash_algorithms: Vec<HashAlgorithm>,
    pub(crate) salt: Vec<u8>,
}

#[repr(u16)]
#[derive(
    Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Copy, Clone, Ord, PartialOrd,
)]
pub enum HashAlgorithm {
    SHA512 = 0x01,
}

impl PreAuthIntegrityCapabilitiesBody {
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

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct EncryptionCapabilitiesBody {
    pub(crate) ciphers: Vec<EncryptionCipher>,
}

#[repr(u16)]
#[derive(
    Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Clone, Ord, PartialOrd, Copy,
)]
pub enum EncryptionCipher {
    AES128GCM = 0x01,
    AES128CCM,
    AES256GCM,
    AES256CCM,
}

impl EncryptionCapabilitiesBody {
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
        Ok((remaining, Self { ciphers }))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        [
            &u16_to_bytes(self.ciphers.len() as u16)[0..],
            &*enum_iter_to_bytes!(self.ciphers.iter()),
        ]
        .concat()
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct CompressionCapabilitiesBody {
    pub(crate) flags: CompressionCapabilitiesFlags,
    pub(crate) compression_algorithms: Vec<CompressionAlgorithm>,
}

#[repr(u32)]
#[derive(
    Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Clone, Ord, PartialOrd, Copy,
)]
pub enum CompressionCapabilitiesFlags {
    None = 0x0,
    Chained,
}

#[repr(u16)]
#[derive(
    Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Clone, Ord, PartialOrd, Copy,
)]
pub enum CompressionAlgorithm {
    None = 0x0,
    Lznt1,
    LZ77,
    Lz77AndHuffman,
    PatternV1,
}

impl CompressionCapabilitiesBody {
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

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct NetnameNegotiateContextIDBody {
    pub(crate) netname: String,
}

impl NetnameNegotiateContextIDBody {
    fn byte_code(&self) -> u16 {
        0x05
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (remaining, name_len) = le_u16(bytes)?;
        let (remaining, _) = take(4_usize)(remaining)?;
        let (remaining, netname) = map_res(take(name_len), |s: &[u8]| {
            let mut vec = s.to_vec();
            vec.retain(|x| *x != 0_u8);
            String::from_utf8(vec)
        })(remaining)?;
        Ok((remaining, Self { netname }))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.netname.bytes().collect::<Vec<u8>>()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize, SMBFromBytes)]
pub struct TransportCapabilitiesBody {
    #[direct(start = 0, length = 4)]
    pub(crate) flags: TransportCapabilitiesFlags,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
    pub struct TransportCapabilitiesFlags: u32 {
        const ACCEPT_TRANSPORT_LEVEL_SECURITY = 0x01;
    }
}

impl SMBFromBytes for TransportCapabilitiesFlags {
    fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> where Self: Sized {
        impl_smb_from_bytes!(u32, input, 4)
    }
}

impl TransportCapabilitiesBody {
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

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct RDMATransformCapabilitiesBody {
    pub(crate) transform_ids: Vec<RDMATransformID>,
}

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Clone, Copy)]
pub enum RDMATransformID {
    None = 0x0,
    Encryption,
    Signing,
}

impl RDMATransformCapabilitiesBody {
    fn byte_code(&self) -> u16 {
        0x07
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (remaining, transform_cnt) = le_u16(bytes)?;
        let (remaining, transform_ids) = count(
            map_res(le_u16, RDMATransformID::try_from),
            transform_cnt as usize,
        )(remaining)?;
        Ok((remaining, Self { transform_ids }))
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

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct SigningCapabilitiesBody {
    pub(crate) signing_algorithms: Vec<SigningAlgorithm>,
}

#[repr(u16)]
#[derive(
    Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Clone, Ord, PartialOrd, Copy,
)]
pub enum SigningAlgorithm {
    HmacSha256 = 0x0,
    AesCmac,
    AesGmac,
}

impl SigningCapabilitiesBody {
    fn byte_code(&self) -> u16 {
        0x08
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (remaining, signing_alg_cnt) = le_u16(bytes)?;
        let (remaining, signing_algorithms) = count(
            map_res(le_u16, SigningAlgorithm::try_from),
            signing_alg_cnt as usize,
        )(remaining)?;
        Ok((remaining, Self { signing_algorithms }))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        [
            &u16_to_bytes(self.signing_algorithms.len() as u16)[0..],
            &*enum_iter_to_bytes!(self.signing_algorithms.iter()),
        ]
        .concat()
    }
}

