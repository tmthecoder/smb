use digest::Digest;
use md4::Md4;

use smb_core::SMBResult;

use crate::byte_helper::u16_to_bytes;
use crate::util::crypto::des::des_long_encrypt;

pub fn authenticate_v1_extended(password: &str, server_challenge: &[u8], lm_response: &[u8], nt_respobse: &[u8]) -> SMBResult<bool> {
    let client_challenge = &lm_response[0..8];
    let expected_v1_response = compute_ntlmv1_extended_response(server_challenge, client_challenge, password)?;

    Ok(nt_respobse == expected_v1_response)
}

fn compute_ntlmv1_extended_response(server_challenge: &[u8], client_challenge: &[u8], password: &str) -> SMBResult<Vec<u8>> {
    let challenge_hash = Md4::new()
        .chain_update(server_challenge)
        .chain_update(client_challenge)
        .finalize();
    let ntof = ntowf_v1(password);

    des_long_encrypt(&ntof, &challenge_hash.as_slice()[0..8])
}

fn ntowf_v1(password: &str) -> Vec<u8> {
    let password = password.encode_utf16().map(u16_to_bytes).collect::<Vec<[u8; 2]>>().concat();
    let mut pass_hash = Md4::new();
    pass_hash.update(password);
    pass_hash.finalize().as_slice().into()
}
