use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use crate::byte_helper::{bytes_to_u16, bytes_to_u32, u16_to_bytes, u32_to_bytes};

macro_rules! ctx_to_bytes {
    ($body: expr) => ({
        let bytes = $body.as_bytes();
        [
            &u16_to_bytes($body.byte_code())[0..],
            &u16_to_bytes(bytes.len() as u16),
            &[0; 4],
            &*bytes
        ].concat()
    });
}

macro_rules! vector_with_only_last {
    ($vector: expr) => ({
        $vector.sort();
        vec![*$vector.last()?]
    })
}

macro_rules! enum_iter_to_bytes {
    ($iter: expr) => ({
        $iter
            .flat_map(|item| u16_to_bytes(*item as u16))
            .collect::<Vec<u8>>()
    })
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NegotiateContext {
    PreAuthIntegrityCapabilities(PreAuthIntegrityCapabilitiesBody),
    EncryptionCapabilities(EncryptionCapabilitiesBody),
    CompressionCapabilities(CompressionCapabilitiesBody),
    NetnameNegotiateContextID(NetnameNegotiateContextIDBody),
    TransportCapabilities(TransportCapabilitiesBody),
    RDMATransformCapabilities(RDMATransformCapabilitiesBody),
    SigningCapabilities(SigningCapabilitiesBody)
}

impl NegotiateContext {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let ctx_type_num = bytes_to_u16(&bytes[0..2]);
        let data_bytes = &bytes[8..];
        match ctx_type_num {
            0x01 => Some(Self::PreAuthIntegrityCapabilities(PreAuthIntegrityCapabilitiesBody::from_bytes(data_bytes)?)),
            0x02 => Some(Self::EncryptionCapabilities(EncryptionCapabilitiesBody::from_bytes(data_bytes)?)),
            0x03 => Some(Self::CompressionCapabilities(CompressionCapabilitiesBody::from_bytes(data_bytes)?)),
            0x05 => Some(Self::NetnameNegotiateContextID(NetnameNegotiateContextIDBody::from_bytes(&bytes[2..])?)),
            0x06 => Some(Self::TransportCapabilities(TransportCapabilitiesBody::from_bytes(data_bytes)?)),
            0x07 => Some(Self::RDMATransformCapabilities(RDMATransformCapabilitiesBody::from_bytes(data_bytes)?)),
            0x08 => Some(Self::SigningCapabilities(SigningCapabilitiesBody::from_bytes(data_bytes)?)),
            _ => None
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
            NegotiateContext::SigningCapabilities(body) => ctx_to_bytes!(body)
        }
    }

    pub fn response_from_existing(&self) -> Option<Self> {
        match self {
            NegotiateContext::PreAuthIntegrityCapabilities(body) => {
                let hash_algorithms = vector_with_only_last!(body.hash_algorithms.clone());
                let mut salt = vec![0_u8; 32];
                rand::rngs::ThreadRng::default().fill_bytes(&mut *salt);
                Some(NegotiateContext::PreAuthIntegrityCapabilities(PreAuthIntegrityCapabilitiesBody { hash_algorithms, salt }))
            }
            NegotiateContext::EncryptionCapabilities(body) => {
                let ciphers = vector_with_only_last!(body.ciphers.clone());
                Some(NegotiateContext::EncryptionCapabilities(EncryptionCapabilitiesBody { ciphers }))
            }
            NegotiateContext::CompressionCapabilities(body) => {
                let compression_algorithms = vector_with_only_last!(body.compression_algorithms.clone());
                Some(NegotiateContext::CompressionCapabilities(CompressionCapabilitiesBody { compression_algorithms, flags: body.flags }))
            }
            NegotiateContext::NetnameNegotiateContextID(_) => {
                Some(NegotiateContext::NetnameNegotiateContextID(NetnameNegotiateContextIDBody { netname: "fakeserver".into() }))
            }
            NegotiateContext::TransportCapabilities(_) => {
                Some(NegotiateContext::TransportCapabilities(TransportCapabilitiesBody { flags: TransportCapabilitiesFlags::empty() }))
            }
            NegotiateContext::RDMATransformCapabilities(_) => {
                Some(NegotiateContext::RDMATransformCapabilities(RDMATransformCapabilitiesBody { transform_ids: vec![RDMATransformID::None] }))
            }
            NegotiateContext::SigningCapabilities(body) => {
                let signing_algorithms = vector_with_only_last!(body.signing_algorithms.clone());
                Some(NegotiateContext::SigningCapabilities(SigningCapabilitiesBody { signing_algorithms }))
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
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Copy, Clone, Ord, PartialOrd)]
pub enum HashAlgorithm {
    SHA512 = 0x01
}

impl PreAuthIntegrityCapabilitiesBody {
    fn byte_code(&self) -> u16 { 0x01 }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let algorithm_cnt = bytes_to_u16(&bytes[0..2]);
        let salt_len = bytes_to_u16(&bytes[2..4]) as usize;
        let mut bytes_ptr = 4_usize;
        let mut hash_algorithms = Vec::new();
        while hash_algorithms.len() < algorithm_cnt as usize {
            hash_algorithms.push(HashAlgorithm::try_from(bytes_to_u16(&bytes[bytes_ptr..(bytes_ptr+2)])).ok()?);
            bytes_ptr += 2;
        }
        let salt = Vec::from(&bytes[bytes_ptr..(bytes_ptr + salt_len)]);
        Some(Self { hash_algorithms, salt })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        [
            &u16_to_bytes(self.hash_algorithms.len() as u16),
            &u16_to_bytes(self.salt.len() as u16),
            &*enum_iter_to_bytes!(self.hash_algorithms.iter()),
            &*self.salt
        ].concat()
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct EncryptionCapabilitiesBody {
    pub(crate) ciphers: Vec<EncryptionCipher>
}

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Clone, Ord, PartialOrd, Copy)]
pub enum EncryptionCipher {
    AES128GCM = 0x01,
    AES128CCM,
    AES256GCM,
    AES256CCM
}

impl EncryptionCapabilitiesBody {
    fn byte_code(&self) -> u16 { 0x02 }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let cipher_cnt = bytes_to_u16(&bytes[0..2]) as usize;
        let mut ciphers = Vec::new();
        let mut cipher_ptr = 2_usize;
        while ciphers.len() < cipher_cnt {
            let cipher = bytes_to_u16(&bytes[cipher_ptr..(cipher_ptr+2)]);
            ciphers.push(EncryptionCipher::try_from(cipher).ok()?);
            cipher_ptr += 2;
        }
        Some(Self { ciphers })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        [
            &u16_to_bytes(self.ciphers.len() as u16)[0..],
            &*enum_iter_to_bytes!(self.ciphers.iter())
        ].concat()
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct CompressionCapabilitiesBody {
    pub(crate) flags: CompressionCapabilitiesFlags,
    pub(crate) compression_algorithms: Vec<CompressionAlgorithm>
}

#[repr(u32)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Clone, Ord, PartialOrd, Copy)]
pub enum CompressionCapabilitiesFlags {
    None = 0x0,
    Chained
}

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Clone, Ord, PartialOrd, Copy)]
pub enum CompressionAlgorithm {
    None = 0x0,
    Lznt1,
    LZ77,
    Lz77AndHuffman,
    PatternV1
}

impl CompressionCapabilitiesBody {
    fn byte_code(&self) -> u16 { 0x03 }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let algorithm_cnt = bytes_to_u16(&bytes[0..2]) as usize;
        let flags = CompressionCapabilitiesFlags::try_from(bytes_to_u32(&bytes[4..8])).ok()?;
        let mut compression_algorithms = Vec::new();
        let mut algorithm_ptr = 8_usize;
        while compression_algorithms.len() < algorithm_cnt {
            let cipher = bytes_to_u16(&bytes[algorithm_ptr..(algorithm_ptr+2)]);
            compression_algorithms.push(CompressionAlgorithm::try_from(cipher).ok()?);
            algorithm_ptr += 2;
        }
        Some(Self { flags, compression_algorithms })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        [
            &u16_to_bytes(self.compression_algorithms.len() as u16)[0..],
            &[0, 0],
            &u32_to_bytes(self.flags as u32),
            &*enum_iter_to_bytes!(self.compression_algorithms.iter())
        ].concat()
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct NetnameNegotiateContextIDBody {
    pub(crate) netname: String
}

impl NetnameNegotiateContextIDBody {
    fn byte_code(&self) -> u16 { 0x05 }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let name_len = bytes_to_u16(&bytes[0..2]) as usize;
        let mut unicode_vec = Vec::from(&bytes[6..(6 + name_len)]);
        unicode_vec.retain(|x| *x != 0_u8);
        let netname = String::from_utf8(unicode_vec).ok()?;
        Some(Self { netname })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.netname.bytes().collect::<Vec<u8>>()
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct TransportCapabilitiesBody {
    pub(crate) flags: TransportCapabilitiesFlags
}

bitflags! {
    #[derive(Serialize, Deserialize)]
    pub struct TransportCapabilitiesFlags: u32 {
        const ACCEPT_TRANSPORT_LEVEL_SECURITY = 0x01;
    }
}

impl TransportCapabilitiesBody {
    fn byte_code(&self) -> u16 { 0x06 }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let flags_num = bytes_to_u32(&bytes[0..4]);
        let flags = TransportCapabilitiesFlags::from_bits_truncate(flags_num);
        Some(Self { flags })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        u32_to_bytes(self.flags.bits).into()
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct RDMATransformCapabilitiesBody {
    pub(crate) transform_ids: Vec<RDMATransformID>
}

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Clone, Copy)]
pub enum RDMATransformID {
    None = 0x0,
    Encryption,
    Signing
}

impl RDMATransformCapabilitiesBody {
    fn byte_code(&self) -> u16 { 0x07 }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let transform_count = bytes_to_u16(&bytes[0..2]) as usize;
        let mut transform_ids = Vec::new();
        let mut transform_id_ptr = 8_usize;
        while transform_ids.len() < transform_count {
            let transform_id_code = bytes_to_u16(&bytes[transform_id_ptr..(transform_id_ptr+2)]);
            let transform_id = RDMATransformID::try_from(transform_id_code).ok()?;
            transform_ids.push(transform_id);
            transform_id_ptr += 2;
        }
        Some(Self { transform_ids })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        [
            &u16_to_bytes(self.transform_ids.len() as u16)[0..],
            &[0; 6],
            &*enum_iter_to_bytes!(self.transform_ids.iter())
        ].concat()
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct SigningCapabilitiesBody {
    pub(crate) signing_algorithms: Vec<SigningAlgorithm>
}

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Clone, Ord, PartialOrd, Copy)]
pub enum SigningAlgorithm {
    HmacSha256 = 0x0,
    AesCmac,
    AesGmac
}

impl SigningCapabilitiesBody {
    fn byte_code(&self) -> u16 { 0x08 }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let singing_alg_cnt = bytes_to_u16(&bytes[0..2]) as usize;
        let mut signing_algorithms = Vec::new();
        let mut signing_alg_ptr = 2;
        while signing_algorithms.len() < singing_alg_cnt {
            let signing_alg_num = bytes_to_u16(&bytes[signing_alg_ptr..(signing_alg_ptr+2)]);
            signing_algorithms.push(SigningAlgorithm::try_from(signing_alg_num).ok()?);
            signing_alg_ptr += 2;
        }
        Some(Self { signing_algorithms })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        [
            &u16_to_bytes(self.signing_algorithms.len() as u16)[0..],
            &*enum_iter_to_bytes!(self.signing_algorithms.iter())
        ].concat()
    }
}