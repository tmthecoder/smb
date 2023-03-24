use std::cmp::min;
use digest::Mac;

pub fn derive_key<T: Mac + Clone>(mac: T, label: &[u8], context: &[u8], key_len_bits: u32) -> Vec<u8> {
    let mut buffer = vec![0_u8; 4 + label.len() + 1 + context.len() + 4];
    for i in 0..label.len() {
        buffer[i+4] = label[i];
    }
    for i in 0..context.len() {
        buffer[i + 5 + label.len()] = context[i];
    }

    let bytes = key_len_bits.to_be_bytes();
    for i in 0..bytes.len() {
        buffer[i + 5 + label.len() + context.len()] = bytes[i];
    }

    let mut num_written = 0;
    let mut num_remaining = key_len_bits / 8;

    let mut output = vec![0_u8; num_remaining as usize];
    let mut j: u32 = 1;
    while num_remaining > 0 {
        let bytes = j.to_be_bytes();
        for i in 0..bytes.len() {
            buffer[i] = bytes[i];
        }
        let k_i = mac.clone()
            .chain_update(&*buffer)
            .finalize()
            .into_bytes();

        let num_to_copy = min(num_remaining, k_i.len() as u32);
        for i in 0..num_to_copy {
            output[(num_written+ i) as usize] = k_i[i as usize];
        }
        num_written += num_to_copy;
        num_remaining -= num_to_copy;
        j += 1;
    }

    output
}