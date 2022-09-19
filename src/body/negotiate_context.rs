use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};
use crate::byte_helper::{bytes_to_u16, bytes_to_u32};

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
        println!("Num: {}", ctx_type_num);
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
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreAuthIntegrityCapabilitiesBody {
    hash_algorithms: Vec<HashAlgorithm>,
    salt: Vec<u8>,
}

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize)]
enum HashAlgorithm {
    SHA512 = 0x01
}

impl PreAuthIntegrityCapabilitiesBody {
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
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EncryptionCapabilitiesBody {
    ciphers: Vec<EncryptionCipher>
}

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize)]
pub enum EncryptionCipher {
    AES128GCM = 0x01,
    AES128CCM,
    AES256GCM,
    AES256CCM
}

impl EncryptionCapabilitiesBody {
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
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompressionCapabilitiesBody {
    flags: CompressionCapabilitiesFlags,
    compression_algorithms: Vec<CompressionAlgorithm>
}

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize)]
pub enum CompressionCapabilitiesFlags {
    None = 0x0,
    Chained
}

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    None = 0x0,
    Lznt1,
    LZ77,
    Lz77AndHuffman,
    PatternV1
}

impl CompressionCapabilitiesBody {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let algorithm_cnt = bytes_to_u16(&bytes[0..2]) as usize;
        let flags = CompressionCapabilitiesFlags::try_from(bytes_to_u16(&bytes[2..4])).ok()?;
        let mut compression_algorithms = Vec::new();
        let mut algorithm_ptr = 8_usize;
        while compression_algorithms.len() < algorithm_cnt {
            let cipher = bytes_to_u16(&bytes[algorithm_ptr..(algorithm_ptr+2)]);
            compression_algorithms.push(CompressionAlgorithm::try_from(cipher).ok()?);
            algorithm_ptr += 2;
        }
        Some(Self { flags, compression_algorithms })
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetnameNegotiateContextIDBody {
    netname: String
}

impl NetnameNegotiateContextIDBody {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let name_len = bytes_to_u16(&bytes[0..2]) as usize;
        let mut unicode_vec = Vec::from(&bytes[6..(6 + name_len)]);
        unicode_vec.retain(|x| *x != 0_u8);
        let netname = String::from_utf8(unicode_vec).ok()?;
        Some(Self { netname })
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransportCapabilitiesBody {
    flags: TransportCapabilitiesFlags
}

bitflags! {
    #[derive(Serialize, Deserialize)]
    pub struct TransportCapabilitiesFlags: u32 {
        const ACCEPT_TRANSPORT_LEVEL_SECURITY = 0x01;
    }
}

impl TransportCapabilitiesBody {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let flags_num = bytes_to_u32(&bytes[0..4]);
        let flags = TransportCapabilitiesFlags::from_bits_truncate(flags_num);
        Some(Self { flags })
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RDMATransformCapabilitiesBody {
    transform_ids: Vec<RDMATransformID>
}

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize)]
pub enum RDMATransformID {
    None = 0x0,
    Encryption,
    Signing
}

impl RDMATransformCapabilitiesBody {
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
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SigningCapabilitiesBody {
    signing_algorithms: Vec<SigningAlgorithm>
}

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    HmacSha256 = 0x0,
    AesCmac,
    AesGmac
}

impl SigningCapabilitiesBody {
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
}