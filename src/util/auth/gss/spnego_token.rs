use serde::{Deserialize, Serialize};

const NEG_TOKEN_INIT_TAG: u8 = 0xA0;
const NEG_TOKEN_RESP_TAG: u8 = 0xA1;

const NEG_STATE_TAG: u8 = 0xA0;

const MECH_TYPE_LIST_TAG: u8 = 0xA0;
const MECH_TOKEN_TAG: u8 = 0xA2;
const MECH_LIST_MIC_TAG: u8 = 0xA3;

const REQUIRED_FLAGS_TAG: u8 = 0xA1;
const APPLICATION_TAG: u8 = 0x60;
const RESPONSE_TOKEN_TAG: u8 = 0xA2;
const SUPPORTED_MECH_TAG: u8 = 0xA1;

const DER_ENCODING_SEQUENCE_TAG: u8 = 0x30;
const DER_ENCODING_OID_TAG: u8 = 0x06;
const DER_ENCODING_BYTE_ARRAY_TAG: u8 = 0x04;

const SPNEGO_ID: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

#[derive(Debug, Deserialize, Serialize)]
pub enum SPNEGOToken {
    Init(SPNEGOTokenInitBody),
    Init2(SPNEGOTokenInit2Body),
    Response(SPNEGOTokenResponseBody),
}

impl SPNEGOToken {
    pub fn from_bytes(bytes: &[u8], offset: &mut usize) -> Option<Self> {
        if bytes[*offset] == APPLICATION_TAG {
            *offset += 1;
            if bytes[*offset + 1] == DER_ENCODING_OID_TAG {
                *offset += 2;
                let oid_length = read_length(bytes, offset);
                let oid = &bytes[*offset..(*offset + oid_length)];
                *offset += oid_length;
                if oid.len() == SPNEGO_ID.len() && *oid == SPNEGO_ID {
                    let tag = bytes[*offset];
                    println!("OID: {:?}", tag);
                    *offset += 1;
                    return match tag {
                        NEG_TOKEN_INIT_TAG => Some(SPNEGOToken::Init(SPNEGOTokenInitBody::from_bytes(bytes, offset)?)),
                        NEG_TOKEN_RESP_TAG => Some(SPNEGOToken::Response(SPNEGOTokenResponseBody::from_bytes(bytes, offset)?)),
                        _ => None,
                    }
                }
            }
        }
        None
    }

    pub fn as_bytes(&self, header: bool) -> Vec<u8> {
        let bytes = match self {
            SPNEGOToken::Init(x) => x.as_bytes(),
            SPNEGOToken::Init2(x) => x.as_bytes(),
            SPNEGOToken::Response(x) => x.as_bytes(),
        };
        if header {
            let oid_size = get_field_size(SPNEGO_ID.len());
            let token_len = 1 + oid_size + bytes.len();
            [
                &[APPLICATION_TAG][0..],
                &get_length(token_len),
                &[DER_ENCODING_SEQUENCE_TAG],
                &get_length(SPNEGO_ID.len()),
                &SPNEGO_ID,
                &bytes
            ].concat()
        } else {
            bytes.to_vec()
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SPNEGOTokenInitBody {
    mech_type_list: Option<Vec<Vec<u8>>>,
    mech_token: Option<Vec<u8>>,
    mech_list_mic: Option<Vec<u8>>
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SPNEGOTokenInit2Body {

}

#[derive(Debug, Deserialize, Serialize)]
pub struct SPNEGOTokenResponseBody {
    state: Option<u8>,
    supported_mech: Option<Vec<u8>>,
    response_token: Option<Vec<u8>>,
    mech_list_mic: Option<Vec<u8>>
}

impl SPNEGOTokenInitBody {

    pub fn from_bytes(bytes: &[u8], offset: &mut usize) -> Option<Self> {
        let slice = &bytes[*offset..];
        if slice[1] != DER_ENCODING_SEQUENCE_TAG { return None;}
        let mut local_offset: usize = 2;
        let seq_len = read_length(slice, &mut local_offset);
        println!("seq len : {} acc len : {}", seq_len, slice.len());
        if slice.len() < local_offset + seq_len { return None; }
        let sequence = &slice[local_offset..(local_offset + seq_len)];
        println!("sequence: {:?}", sequence);
        let mut ptr = 0;
        let mut mech_type_list = None;
        let mut mech_token = None;
        let mut mech_list_mic = None;
        while ptr < sequence.len() {
            let tag = sequence[ptr];
            ptr += 1;
            println!("tag {}", tag);
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
        *offset = local_offset + seq_len;
        Some(SPNEGOTokenInitBody { mech_type_list, mech_token, mech_list_mic})
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

impl SPNEGOTokenInit2Body {
    fn as_bytes(&self) -> Vec<u8> {Vec::new()}
}

impl SPNEGOTokenResponseBody {
    fn as_bytes(&self) -> Vec<u8> {Vec::new()}

    fn from_bytes(bytes: &[u8], offset: &mut usize) -> Option<Self> {
        None
    }
}

// Private static helper methods (reading methods)
impl SPNEGOTokenInitBody {
    fn read_mech_type_list(buffer: &[u8], offset: &mut usize) -> Option<Vec<Vec<u8>>> {
        let mut mech_type_list = Vec::new();
        if buffer[*offset + 1] != DER_ENCODING_SEQUENCE_TAG {
            return None;
        }
        *offset += 2;
        println!("CVal : {}", buffer[*offset]);
        let seq_len = read_length(buffer, offset);
        if buffer.len() < *offset + seq_len { return None; }
        let sequence = &buffer[*offset..(*offset + seq_len)];
        let mut ptr = 0;
        while ptr < sequence.len() {
            let tag = sequence[ptr];
            ptr += 1;
            if tag != DER_ENCODING_OID_TAG { return None; }
            let mech_type_len = read_length(sequence, &mut ptr);
            let mech_type = &sequence[ptr..(ptr + mech_type_len)];
            mech_type_list.push(mech_type.to_vec());
            ptr += mech_type_len;
        }
        *offset += seq_len;
        Some(mech_type_list)
    }

    fn read_mech_token(buffer: &[u8], offset: &mut usize) -> Option<Vec<u8>> {
        if buffer[*offset + 1] != DER_ENCODING_BYTE_ARRAY_TAG { return None; }
        *offset += 2;
        let seq_len = read_length(buffer, offset);
        if buffer.len() < *offset + seq_len { return None; }
        let start = *offset;
        *offset += seq_len;
        println!("Size: {}", buffer[start..(start + seq_len)].len());
        Some(buffer[start..(start + seq_len)].to_vec())
    }

    fn read_mech_list_mic(buffer: &[u8], offset: &mut usize) -> Option<Vec<u8>> {
        if buffer[*offset + 1]!= DER_ENCODING_BYTE_ARRAY_TAG { return None; }
        *offset += 2;
        let seq_len = read_length(buffer, offset);
        if buffer.len() < *offset + seq_len { return None; }
        let start = *offset;
        *offset += seq_len;
        Some(buffer[start..(start + seq_len)].to_vec())
    }
}

// Private helper methods (writing methods)
impl SPNEGOTokenInitBody {
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
        if let Some(_) = &self.mech_type_list {
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





fn read_length(buffer: &[u8], offset: &mut usize) -> usize {
    let mut len = buffer[*offset] as usize;
    *offset += 1;
    if len >= 0x80 {
        let field_size = (len & 0x7F);
        len = 0;
        for byte in &buffer[*offset..field_size] {
            len *= 256;
            len += (*byte) as usize;
        }
        *offset += field_size;
    }
    len
}

fn get_field_size(len: usize) -> usize {
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

fn get_length(length: usize) -> Vec<u8> {
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