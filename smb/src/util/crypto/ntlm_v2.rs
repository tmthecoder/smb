use digest::Digest;
use hmac::{Hmac, Mac};
use md4::Md4;
use md5::Md5;

use smb_core::error::SMBError;
use smb_core::SMBResult;

use crate::byte_helper::u16_to_bytes;

pub fn authenticate_v2(domain: &str, account: &str, password: &str, server_challenge: &[u8], lm_response: &[u8], nt_response: &[u8]) -> SMBResult<(bool, Vec<u8>)> {
    let resp = if lm_response.len() == 24 {
        let lm_client_challenge = &lm_response[16..24];
        let expected_resp = compute_lmv2_response(server_challenge, lm_client_challenge, password, account, domain)?;
        expected_resp == lm_response
    } else { false };

    let resp = if nt_response.len() >= 16 && !resp {
        let client_nt_proof = &nt_response[0..16];
        let client_structure_padded = &nt_response[16..];
        let expected_nt_proof = compute_ntlmv2_proof(server_challenge, client_structure_padded, password, account, domain)?;
        client_nt_proof == expected_nt_proof
    } else { resp };

    if resp {
        let response_key_nt = ntowf_v2(password, account, domain)?;
        let nt_proof_str = &nt_response[0..16];
        let res = new_hmac_from_slice(&response_key_nt)?
            .chain_update(nt_proof_str).finalize().into_bytes().as_slice().into();
        Ok((resp, res))
    } else {
        Ok((resp, Vec::new()))
    }
}

fn compute_lmv2_response(server_challenge: &[u8], lm_client_challenge: &[u8], password: &str, account: &str, domain: &str) -> SMBResult<Vec<u8>> {
    let key = lmowf_v2(password, account, domain)?;
    let bytes_hmac = new_hmac_from_slice(&key)?;
    let bytes_hmac = bytes_hmac
        .chain_update(server_challenge)
        .chain_update(lm_client_challenge);
    let result = hmac::Mac::finalize(bytes_hmac);
    Ok([result.into_bytes().as_slice(), lm_client_challenge].concat())
}

fn compute_ntlmv2_proof(server_challenge: &[u8], client_structure_padded: &[u8], password: &str, account: &str, domain: &str) -> SMBResult<Vec<u8>> {
    let key = ntowf_v2(password, account, domain)?;
    let temp = client_structure_padded;
    let bytes_hmac = new_hmac_from_slice(&key)?;
    let bytes_hmac = bytes_hmac
        .chain_update(server_challenge)
        .chain_update(temp);
    let result = hmac::Mac::finalize(bytes_hmac);
    Ok(result.into_bytes().as_slice().into())
}

fn lmowf_v2(password: &str, user: &str, domain: &str) -> SMBResult<Vec<u8>> {
    ntowf_v2(password, user, domain)
}

fn ntowf_v2(password: &str, user: &str, domain: &str) -> SMBResult<Vec<u8>> {
    let password = password.encode_utf16().map(u16_to_bytes).collect::<Vec<[u8; 2]>>().concat();
    let password_hash = Md4::digest(&password);
    let text = user.to_uppercase() + domain;
    let bytes = text.encode_utf16().map(u16_to_bytes).collect::<Vec<[u8; 2]>>().concat();
    let mut hmac_md5 = new_hmac_from_slice(password_hash.as_slice())?;
    hmac_md5.update(&bytes);
    let result = hmac::Mac::finalize(hmac_md5);
    Ok(result.into_bytes().to_vec())
}

fn new_hmac_from_slice(slice: &[u8]) -> SMBResult<Hmac<Md5>> {
    <Hmac<Md5>>::new_from_slice(slice).map_err(|_| SMBError::CryptoError("Invalid length for key"))
}