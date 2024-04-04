use std::cmp::min;

use digest::Mac;

pub fn derive_key<T: Mac + Clone>(mac: T, label: &[u8], context: &[u8], key_len_bits: u32) -> Vec<u8> {
    let mut buffer = vec![0_u8; 4 + label.len() + 1 + context.len() + 4];
    buffer[4..(label.len() + 4)].copy_from_slice(label);

    let ctx_start = 5 + label.len();
    let ctx_end = ctx_start + context.len();
    buffer[ctx_start..ctx_end].copy_from_slice(context);

    let bytes = key_len_bits.to_be_bytes();
    let b_start = 5 + label.len() + context.len();
    let b_end = b_start + bytes.len();
    buffer[b_start..b_end].copy_from_slice(&bytes);

    let mut num_written = 0;
    let mut num_remaining = key_len_bits / 8;

    let mut output = vec![0_u8; num_remaining as usize];
    let mut j: u32 = 1;
    while num_remaining > 0 {
        let bytes = j.to_be_bytes();

        buffer[..bytes.len()].copy_from_slice(&bytes[..]);

        let k_i = mac.clone()
            .chain_update(&*buffer)
            .finalize()
            .into_bytes();

        let num_to_copy = min(num_remaining, k_i.len() as u32);
        output[(num_written as usize)..(num_written + num_to_copy) as usize]
            .copy_from_slice(&k_i[0..num_to_copy as usize]);

        num_written += num_to_copy;
        num_remaining -= num_to_copy;
        j += 1;
    }

    output
}