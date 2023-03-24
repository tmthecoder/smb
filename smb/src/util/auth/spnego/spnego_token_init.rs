use nom::Err::Error;
use nom::error::ErrorKind;
use nom::IResult;
use nom::multi::many0;
use nom::number::complete::le_u8;
use serde::{Deserialize, Serialize};

use crate::util::auth::AuthProvider;
use crate::util::auth::spnego::der_utils::{DER_ENCODING_BYTE_ARRAY_TAG, DER_ENCODING_OID_TAG, DER_ENCODING_SEQUENCE_TAG, encode_der_bytes, get_array_field_len, get_field_size, get_length, MECH_LIST_MIC_TAG, MECH_TOKEN_TAG, MECH_TYPE_LIST_TAG, NEG_TOKEN_INIT_TAG, parse_der_byte_array, parse_der_multibyte, parse_field_with_len, parse_length};

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct SPNEGOTokenInitBody<T: AuthProvider> {
    mechanism: Option<T>,
    mech_type_list: Option<Vec<Vec<u8>>>,
    pub mech_token: Option<Vec<u8>>,
    mech_list_mic: Option<Vec<u8>>,
}

impl<T: AuthProvider> Default for SPNEGOTokenInitBody<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: AuthProvider> SPNEGOTokenInitBody<T> {
    pub fn new() -> Self {
        let mech_type_list = Some(vec![T::get_oid()]);
        Self {
            mechanism: None,
            mech_type_list,
            mech_token: None,
            mech_list_mic: None,
        }
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (remaining, _) = parse_length(bytes)?;
        let (remaining, mut tag) = le_u8(remaining)?;
        if tag != DER_ENCODING_SEQUENCE_TAG { return Err(Error(nom::error::Error::new(remaining, ErrorKind::Fail))) }
        let (remaining, mut sequence) = parse_field_with_len(remaining)?;
        let mut mech_type_list = None;
        let mut mech_token = None;
        let mut mech_list_mic = None;
        while !sequence.is_empty() {
            (sequence, tag) = le_u8(sequence)?;
            match tag {
                MECH_TYPE_LIST_TAG => {
                    let (s, list) = Self::parse_mech_type_list(sequence)?;
                    sequence = s;
                    mech_type_list = Some(list);
                },
                MECH_TOKEN_TAG => {
                    let (s, token) = Self::parse_mech_token(sequence)?;
                    sequence = s;
                    mech_token = Some(token);
                },
                MECH_LIST_MIC_TAG => {
                    let (s, mic) = Self::parse_mech_list_mic(sequence)?;
                    sequence = s;
                    mech_list_mic = Some(mic);
                },
                _ => return Err(Error(nom::error::Error::new(remaining, ErrorKind::Fail))),
            }
        }
        Ok((remaining, SPNEGOTokenInitBody { mechanism: None, mech_type_list, mech_token, mech_list_mic }))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let seq_len = self.token_fields_len();
        let seq_len_field_size = get_field_size(seq_len);
        let construction_len = 1 + seq_len_field_size + seq_len;

        // Write initial neg token tag & construction length
        bytes.push(NEG_TOKEN_INIT_TAG);
        bytes.append(&mut get_length(construction_len));
        // Write der encoding tag & sequence length
        bytes.push(DER_ENCODING_SEQUENCE_TAG);
        bytes.append(&mut get_length(seq_len));

        // Write mechanism type list if it's not null
        if let Some(mech_type_list) = &self.mech_type_list {
            bytes.append(&mut encode_der_bytes(mech_type_list, MECH_TYPE_LIST_TAG, DER_ENCODING_SEQUENCE_TAG, DER_ENCODING_OID_TAG));
        }
        // Write mechanism token if it's not null
        if let Some(mech_token) = &self.mech_token {
            bytes.append(&mut encode_der_bytes(mech_token, MECH_TOKEN_TAG, DER_ENCODING_BYTE_ARRAY_TAG, 0));
        }
        // Write mechanism list mic if it's not null
        if let Some(mech_list_mic) = &self.mech_list_mic {
            bytes.append(&mut encode_der_bytes(mech_list_mic, MECH_LIST_MIC_TAG, DER_ENCODING_BYTE_ARRAY_TAG, 0));
        }
        bytes
    }
}

// Private static helper methods (reading methods)
impl<T: AuthProvider> SPNEGOTokenInitBody<T> {
    fn parse_mech_type_list(buffer: &[u8]) -> IResult<&[u8], Vec<Vec<u8>>> {
        let (remaining, _) = parse_length(buffer)?;
        let (remaining, tag) = le_u8(remaining)?;
        if tag != DER_ENCODING_SEQUENCE_TAG { return Err(Error(nom::error::Error::new(remaining, ErrorKind::Fail))) }
        let (remaining, sequence) = parse_field_with_len(remaining)?;
        let (_, list) = many0(|buf| parse_der_multibyte(buf, DER_ENCODING_OID_TAG))(sequence)?;
        Ok((remaining, list))
    }

    fn parse_mech_token(buffer: &[u8]) -> IResult<&[u8], Vec<u8>> {
        parse_der_byte_array(buffer)
    }

    fn parse_mech_list_mic(buffer: &[u8]) -> IResult<&[u8], Vec<u8>> {
        parse_der_byte_array(buffer)
    }
}

// Private helper methods (writing methods)
impl<T: AuthProvider> SPNEGOTokenInitBody<T> {
    fn token_fields_len(&self) -> usize {
        let mut len = 0;
        if let Some(mech_type_list) = &self.mech_type_list {
            len += get_array_field_len(mech_type_list);
        }
        if let Some(mech_token) = &self.mech_token {
            len += get_array_field_len(mech_token);
        }
        if let Some(mech_list_mic) = &self.mech_list_mic {
            len += get_array_field_len(mech_list_mic);
        }
        len
    }
}
