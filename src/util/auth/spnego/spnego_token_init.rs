use nom::IResult;
use nom::Err::Error;
use nom::error::ErrorKind;
use nom::multi::many0;
use nom::number::complete::le_u8;
use serde::{Deserialize, Serialize};

use crate::util::auth::AuthProvider;
use crate::util::auth::spnego::util::{DER_ENCODING_BYTE_ARRAY_TAG, DER_ENCODING_OID_TAG, DER_ENCODING_SEQUENCE_TAG, get_field_size, get_length, MECH_LIST_MIC_TAG, MECH_TOKEN_TAG, MECH_TYPE_LIST_TAG, NEG_TOKEN_INIT_TAG, parse_der_byte_array, parse_der_multibyte, parse_field_with_len, parse_length};

#[derive(Debug, Deserialize, Serialize)]
pub struct SPNEGOTokenInitBody<T: AuthProvider> {
    mechanism: Option<T>,
    mech_type_list: Option<Vec<Vec<u8>>>,
    pub mech_token: Option<Vec<u8>>,
    mech_list_mic: Option<Vec<u8>>
}

impl<T: AuthProvider> SPNEGOTokenInitBody<T> {
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
            bytes.append(&mut self.mech_list_bytes(mech_type_list));
        }
        // Write mechanism token if it's not null
        if let Some(mech_token) = &self.mech_token {
            bytes.append(&mut self.mech_token_bytes(mech_token));
        }
        // Write mechanism list mic if it's not null
        if let Some(mech_list_mic) = &self.mech_list_mic {
            bytes.append(&mut self.mech_list_mic_bytes(mech_list_mic));
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
    fn mech_list_bytes(&self, mech_type_list: &[Vec<u8>]) -> Vec<u8> {
        let seq_len = self.mech_list_len();
        let seq_len_field_size = get_field_size(seq_len);
        let constriction_len = 1 + seq_len_field_size + seq_len;
        [
            &[MECH_TYPE_LIST_TAG][0..],
            &*get_length(constriction_len),
            &[DER_ENCODING_SEQUENCE_TAG],
            &*get_length(seq_len),
            &*mech_type_list.iter().flat_map(|mech_type| {
                [
                    &[DER_ENCODING_OID_TAG][0..],
                    &*get_length(mech_type.len()),
                    mech_type
                ].concat()
            }).collect::<Vec<u8>>()
        ].concat()
    }

    fn mech_token_bytes(&self, mech_token: &Vec<u8>) -> Vec<u8> {
        let construction_len = 1 + get_field_size(mech_token.len()) + mech_token.len();
        [
            &[MECH_TOKEN_TAG][0..],
            &*get_length(construction_len),
            &[DER_ENCODING_BYTE_ARRAY_TAG],
            &*get_length(mech_token.len()),
            mech_token
        ].concat()
    }

    fn mech_list_mic_bytes(&self, mech_list_mic: &Vec<u8>) -> Vec<u8> {
        let mech_list_mic_field_size = get_field_size(mech_list_mic.len());
        [
            &[MECH_LIST_MIC_TAG][0..],
            &*get_length(1 + mech_list_mic_field_size + mech_list_mic.len()),
            &[DER_ENCODING_BYTE_ARRAY_TAG],
            &get_length(mech_list_mic.len()),
            mech_list_mic
        ].concat()
    }

    fn mech_list_len(&self) -> usize {
        if let Some(mech_type_list) = &self.mech_type_list {
            mech_type_list.iter().fold(0, |prev, mech_type| {
                let type_field_size = get_field_size(mech_type.len());
                let entry_len = 1 + type_field_size + mech_type.len();
                prev + entry_len
            })
        } else {
            0
        }
    }

    fn token_fields_len(&self) -> usize {
        let mut len = 0;
        if self.mech_type_list.is_some() {
            let list_sequence_len = self.mech_list_len();
            let list_sequence_len_field_size = get_field_size(list_sequence_len);
            let list_construction_len = 1 + list_sequence_len_field_size + list_sequence_len;
            let list_construction_len_field_size = get_field_size(list_construction_len);
            let entry_len = 1 + list_construction_len_field_size + 1 + list_sequence_len_field_size + list_sequence_len;
            len += entry_len;
        }
        if let Some(mech_token) = &self.mech_token {
            let token_field_size = get_field_size(mech_token.len());
            let token_construction_len = 1 + token_field_size + mech_token.len();
            let token_construction_len_field_size = get_field_size(token_construction_len);
            let entry_len = 1 + token_construction_len_field_size + 1 + token_field_size + mech_token.len();
            len += entry_len;
        }
        if let Some(mech_list_mic) = &self.mech_list_mic {
            let mech_list_mic_field_size = get_field_size(mech_list_mic.len());
            let mech_list_mic_construction_len = 1 + mech_list_mic_field_size + mech_list_mic.len();
            let mech_list_mic_construction_len_field_size = get_field_size(mech_list_mic_construction_len);
            let entry_len = 1 + mech_list_mic_construction_len_field_size + 1 + mech_list_mic_field_size + mech_list_mic.len();
            len += entry_len;
        }
        len
    }
}
