use crate::util::auth::AuthProvider;
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};
use crate::util::auth::spnego::util::{DER_ENCODING_SEQUENCE_TAG, read_length, NEG_STATE_TAG, SUPPORTED_MECH_TAG, RESPONSE_TOKEN_TAG, MECH_LIST_MIC_TAG, DER_ENCODING_ENUM_TAG, DER_ENCODING_OID_TAG, DER_ENCODING_BYTE_ARRAY_TAG, read_der_byte_array, read_der_oid};

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive, Deserialize, Serialize)]
pub enum NegotiateState {
    AcceptCompleted = 0x0,
    AcceptIncomplete,
    Reject,
    RequestMic,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SPNEGOTokenResponseBody<T: AuthProvider> {
    mechanism: Option<T>,
    state: Option<NegotiateState>,
    supported_mech: Option<Vec<u8>>,
    pub response_token: Option<Vec<u8>>,
    mech_list_mic: Option<Vec<u8>>
}

impl<T: AuthProvider> SPNEGOTokenResponseBody<T> {
    pub fn as_bytes(&self) -> Vec<u8> {Vec::new()}

    pub fn from_bytes(bytes: &[u8], offset: &mut usize) -> Option<Self> {
        let _ = read_length(bytes, offset);
        if bytes[*offset] != DER_ENCODING_SEQUENCE_TAG { return None;}
        *offset += 1;
        let seq_len = read_length(bytes, offset);
        if bytes.len() < *offset + seq_len { return None; }

        let sequence = &bytes[*offset..(*offset + seq_len)];
        let mut ptr = 0;

        let mut state = None;
        let mut supported_mech = None;
        let mut response_token = None;
        let mut mech_list_mic = None;

        while ptr < sequence.len() {
            let tag = sequence[ptr];
            ptr += 1;
            println!("Tag: {}", tag);
            match tag {
                NEG_STATE_TAG => {
                    state = Self::read_negotiate_state(sequence, &mut ptr);
                },
                SUPPORTED_MECH_TAG => {
                    supported_mech = Self::read_supported_mech(sequence, &mut ptr);
                },
                RESPONSE_TOKEN_TAG => {
                    response_token = Self::read_response_token(sequence, &mut ptr);
                },
                MECH_LIST_MIC_TAG => {
                    mech_list_mic = Self::read_mech_list_mic(sequence, &mut ptr);
                },
                _ => return None,
            }
        }

        *offset += seq_len;
        Some(SPNEGOTokenResponseBody { mechanism: None, state, supported_mech, response_token, mech_list_mic})
    }
}

// Private static helper methods
impl<T: AuthProvider> SPNEGOTokenResponseBody<T> {
    fn read_negotiate_state(buffer: &[u8], offset: &mut usize) -> Option<NegotiateState> {
        let _ = read_length(buffer, offset);
        if buffer[*offset] != DER_ENCODING_ENUM_TAG { return None; };
        let _ = read_length(buffer, offset);
        let state = NegotiateState::try_from(buffer[*offset]).ok();
        *offset += 1;
        state
    }

    fn read_supported_mech(buffer: &[u8], offset: &mut usize) -> Option<Vec<u8>> {
        read_der_oid(buffer, offset)
    }

    fn read_response_token(buffer: &[u8], offset: &mut usize) -> Option<Vec<u8>> {
       read_der_byte_array(buffer, offset) 
    }

    fn read_mech_list_mic(buffer: &[u8], offset: &mut usize) -> Option<Vec<u8>> {
        read_der_byte_array(buffer, offset)
    }
}