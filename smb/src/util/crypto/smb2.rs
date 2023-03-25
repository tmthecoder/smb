use aes::Aes128;
use cmac::Cmac;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use smb_core::error::SMBError;

use crate::protocol::body::SMBDialect;
use crate::util::crypto::sp800_108;

pub fn calculate_signature(signing_key: &[u8], dialect: SMBDialect, buffer: &[u8], offset: usize, padded_len: usize) -> Result<Vec<u8>, anyhow::Error>{
    let buffer = &buffer[offset..(offset + padded_len)];
    let output = if dialect == SMBDialect::V2_0_2 || dialect == SMBDialect::V2_1_0 {
        <Hmac<Sha256>>::new_from_slice(signing_key)?
            .chain_update(buffer)
            .finalize()
            .into_bytes()
            .to_vec()
    } else {
        <Cmac<Aes128>>::new_from_slice(signing_key)?
            .chain_update(buffer)
            .finalize()
            .into_bytes()
            .to_vec()
    };
    Ok(output)
}
pub fn generate_signing_key(session_key: &[u8], dialect: SMBDialect, preauth_integrity_hash_value: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    if dialect == SMBDialect::V2_0_2 || dialect == SMBDialect::V2_1_0 {
        return Ok(session_key.into());
    }

    if dialect == SMBDialect::V3_1_1 && preauth_integrity_hash_value.is_empty() {
        return Err(SMBError::PreconditionFailed("No preauth_integrity_hash_value with SMB 3.1.1".into()).into());
    }

    let label: &[u8] = if dialect == SMBDialect::V3_1_1 {
        b"SMBSigningKey\0"
    } else {
        b"SMB2AESCMAC\0"
    };
    let context = if dialect == SMBDialect::V3_1_1 {
        preauth_integrity_hash_value
    } else {
        b"SmbSign\0"
    };

    let hmac = <Hmac<Sha256>>::new_from_slice(session_key)?;
    Ok(sp800_108::derive_key(hmac, label, context, 128))
}