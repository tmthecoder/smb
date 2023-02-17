pub const NEG_TOKEN_INIT_TAG: u8 = 0xA0;
pub const NEG_TOKEN_RESP_TAG: u8 = 0xA1;

pub const NEG_STATE_TAG: u8 = 0xA0;

pub const MECH_TYPE_LIST_TAG: u8 = 0xA0;
pub const MECH_TOKEN_TAG: u8 = 0xA2;
pub const MECH_LIST_MIC_TAG: u8 = 0xA3;

pub const REQUIRED_FLAGS_TAG: u8 = 0xA1;
pub const APPLICATION_TAG: u8 = 0x60;
pub const RESPONSE_TOKEN_TAG: u8 = 0xA2;
pub const SUPPORTED_MECH_TAG: u8 = 0xA1;

pub const DER_ENCODING_ENUM_TAG: u8 = 0x0A;
pub const DER_ENCODING_SEQUENCE_TAG: u8 = 0x30;
pub const DER_ENCODING_OID_TAG: u8 = 0x06;
pub const DER_ENCODING_BYTE_ARRAY_TAG: u8 = 0x04;

pub const SPNEGO_ID: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

pub fn read_length(buffer: &[u8], offset: &mut usize) -> usize {
    let mut len = buffer[*offset] as usize;
    *offset += 1;
    if len >= 0x80 {
        let field_size = len & 0x7F;
        len = 0;
        for byte in &buffer[*offset..(*offset + field_size)] {
            len *= 256;
            len += (*byte) as usize;
        }
        *offset += field_size;
    }
    len
}

pub fn get_field_size(len: usize) -> usize {
    if len < 0x80 {
        return 1;
    }
    let mut adder = 1;
    let mut len = len;
    while len > 0 {
        len /= 256;
        adder+=1;
    }
    adder
}

pub fn get_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }
    let mut len = length;
    let mut len_bytes = Vec::new();
    while len > 0 {
        let byte = len % 256;
        len_bytes.push(byte as u8);
        len /= 256;
    }
    len_bytes.reverse();
    [&[(0x80 | len_bytes.len()) as u8][0..], &*len_bytes].concat()
}

pub fn read_der_oid(buffer: &[u8], offset: &mut usize) -> Option<Vec<u8>> {
    let _ = read_length(buffer, offset);
    read_der_multibyte(buffer, offset, DER_ENCODING_OID_TAG)
}

pub fn read_der_byte_array(buffer: &[u8], offset: &mut usize) -> Option<Vec<u8>> {
    let _ = read_length(buffer, offset);
    read_der_multibyte(buffer, offset, DER_ENCODING_BYTE_ARRAY_TAG)
}

pub fn read_der_multibyte(buffer: &[u8], offset: &mut usize, type_tag: u8) -> Option<Vec<u8>> {
    // let _ = read_length(buffer, offset);
    if buffer[*offset] != type_tag { return None; }
    *offset += 1;
    let length = read_length(buffer, offset);
    if buffer.len() < *offset + length { return None; }
    let start = *offset;
    *offset += length;
    Some(buffer[start..(start + length)].to_vec())
}