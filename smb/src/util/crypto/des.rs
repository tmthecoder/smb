use des::cipher::BlockEncrypt;
use des::Des;
use digest::KeyInit;

use smb_core::error::SMBError;
use smb_core::SMBResult;

pub fn des_long_encrypt(key: &[u8], plaintext: &[u8]) -> SMBResult<Vec<u8>> {
    if key.len() != 16 || plaintext.len() != 8 { return Err(SMBError::crypto_error("Invalid key length")); }
    let padded = [key, &*vec![0; 21 - key.len()]].concat();

    let k1 = &padded[0..7];
    let k2 = &padded[7..14];
    let k3 = &padded[14..21];

    let r1 = des_encrypt(&extend_des_key(k1), plaintext);
    let r2 = des_encrypt(&extend_des_key(k2), plaintext);
    let r3 = des_encrypt(&extend_des_key(k3), plaintext);

    Ok([r1?, r2?, r3?].concat())
}

fn extend_des_key(key: &[u8]) -> Vec<u8> {
    let mut result = vec![0; 8];

    result[0] = key[0] >> 1;
    result[1] = ((key[0] & 0x01) << 6) | (key[1] >> 2);
    result[2] = ((key[1] & 0x03) << 5) | (key[2] >> 3);
    result[3] = ((key[2] & 0x07) << 4) | (key[3] >> 4);
    result[4] = ((key[3] & 0x0F) << 3) | (key[4] >> 5);
    result[5] = ((key[4] & 0x1F) << 2) | (key[5] >> 6);
    result[6] = ((key[5] & 0x3F) << 1) | (key[6] >> 7);
    result[7] = key[6] & 0x7F;

    for i in 0..result.len() {
        result[i] <<= 1;
    }

    result
}

fn des_encrypt(key: &[u8], plaintext: &[u8]) -> SMBResult<Vec<u8>> {
    let des = Des::new_from_slice(key)
        .map_err(|_| SMBError::crypto_error("Invalid key length"))?;
    let mut result = vec![0_u8; plaintext.len()];
    des.encrypt_block_b2b(plaintext.into(), (&mut *result).into());
    Ok(result)
}
