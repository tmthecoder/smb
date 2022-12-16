use crate::util::auth::AuthProvider;
use serde::{Deserialize, Serialize};
use crate::util::auth::spnego::util::{DER_ENCODING_BYTE_ARRAY_TAG, DER_ENCODING_OID_TAG, DER_ENCODING_SEQUENCE_TAG, get_field_size, get_length, MECH_LIST_MIC_TAG, MECH_TOKEN_TAG, MECH_TYPE_LIST_TAG, NEG_TOKEN_INIT_TAG, read_der_byte_array, read_der_multibyte, read_der_oid, read_length, REQUIRED_FLAGS_TAG};

#[derive(Debug, Deserialize, Serialize)]
pub struct SPNEGOTokenInitBody<T: AuthProvider> {
    mechanism: Option<T>,
    mech_type_list: Option<Vec<Vec<u8>>>,
    pub mech_token: Option<Vec<u8>>,
    mech_list_mic: Option<Vec<u8>>
}

impl<T: AuthProvider> SPNEGOTokenInitBody<T> {

    pub fn from_bytes(bytes: &[u8], offset: &mut usize) -> Option<Self> {
        let _ = read_length(bytes, offset);
        if bytes[*offset] != DER_ENCODING_SEQUENCE_TAG { return None;}
        *offset += 1;
        let seq_len = read_length(bytes, offset);
        if bytes.len() < *offset + seq_len { return None; }

        let sequence = &bytes[*offset..(*offset + seq_len)];
        let mut ptr = 0;

        let mut mech_type_list = None;
        let mut mech_token = None;
        let mut mech_list_mic = None;
        while ptr < sequence.len() {
            let tag = sequence[ptr];
            ptr += 1;
            match tag {
                MECH_TYPE_LIST_TAG => {
                    mech_type_list = Self::read_mech_type_list(sequence, &mut ptr);
                },
                REQUIRED_FLAGS_TAG => return None,
                MECH_TOKEN_TAG => {
                    mech_token = Self::read_mech_token(sequence, &mut ptr);
                },
                MECH_LIST_MIC_TAG => {
                    mech_list_mic = Self::read_mech_list_mic(sequence, &mut ptr);
                },
                _ => return None,
            }
        }
        *offset += seq_len;
        Some(SPNEGOTokenInitBody { mechanism: None, mech_type_list, mech_token, mech_list_mic})
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
    fn read_mech_type_list(buffer: &[u8], offset: &mut usize) -> Option<Vec<Vec<u8>>> {
        let mut mech_type_list = Vec::new();
        let _ = read_length(buffer, offset);
        if buffer[*offset] != DER_ENCODING_SEQUENCE_TAG { return None; }
        *offset += 1;
        let seq_len = read_length(buffer, offset);
        if buffer.len() < *offset + seq_len { return None; }
        let sequence = &buffer[*offset..(*offset + seq_len)];
        let mut ptr = 0;
        while ptr < sequence.len() {
            mech_type_list.push(read_der_multibyte(sequence, &mut ptr, DER_ENCODING_OID_TAG)?);
        }
        *offset += seq_len;
        Some(mech_type_list)
    }

    fn read_mech_token(buffer: &[u8], offset: &mut usize) -> Option<Vec<u8>> {
       read_der_byte_array(buffer, offset)
    }

    fn read_mech_list_mic(buffer: &[u8], offset: &mut usize) -> Option<Vec<u8>> {
       read_der_byte_array(buffer, offset)
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