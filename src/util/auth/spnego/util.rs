use nom::bytes::complete::take;
use nom::combinator::map;
use nom::Err::Error;
use nom::error::ErrorKind;
use nom::IResult;
use nom::multi::fold_many_m_n;
use nom::number::complete::le_u8;

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

pub fn parse_length(buffer: &[u8]) -> IResult<&[u8], usize> {
    let (remaining, len) = le_u8(buffer)?;
    if len < 0x80 { return Ok((remaining, len as usize)); }
    let field_size = (len & 0x7f) as usize;
    fold_many_m_n(field_size, field_size, le_u8, || 0_usize, |len, item| len * 256 + item as usize)(remaining)
}

pub fn parse_field_with_len(buffer: &[u8]) -> IResult<&[u8], &[u8]> {
    parse_length(buffer).and_then(|(remaining, len)| {
        println!("len: {len}");
        take(len)(remaining)
    })
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

pub fn parse_der_oid(buffer: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (remaining, _) = parse_length(buffer)?;
    parse_der_multibyte(remaining, DER_ENCODING_OID_TAG)
}

pub fn parse_der_byte_array(buffer: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (remaining, _) = parse_length(buffer)?;
    parse_der_multibyte(remaining, DER_ENCODING_BYTE_ARRAY_TAG)
}

pub fn parse_der_multibyte(buffer: &[u8], tag: u8) -> IResult<&[u8], Vec<u8>> {
    let (remaining, b_tag) = le_u8(buffer)?;
    if tag != b_tag { return Err(Error(nom::error::Error::new(remaining, ErrorKind::Fail))); }
    map(parse_field_with_len, |buf| buf.to_vec())(remaining)
}