use nom::combinator::map_res;
use nom::Err::Error;
use nom::error::ErrorKind;
use nom::IResult;
use nom::number::complete::le_u8;
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use crate::util::as_bytes::AsByteVec;
use crate::util::auth::AuthProvider;
use crate::util::auth::nt_status::NTStatus;
use crate::util::auth::spnego::der_utils::{DER_ENCODING_BYTE_ARRAY_TAG, DER_ENCODING_ENUM_TAG, DER_ENCODING_OID_TAG, DER_ENCODING_SEQUENCE_TAG, encode_der_bytes, get_array_field_len, get_field_size, get_length, MECH_LIST_MIC_TAG, NEG_STATE_TAG, NEG_TOKEN_RESP_TAG, parse_der_byte_array, parse_der_oid, parse_field_with_len, parse_length, RESPONSE_TOKEN_TAG, SUPPORTED_MECH_TAG};

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
    mech_list_mic: Option<Vec<u8>>,
}

impl<T: AuthProvider> SPNEGOTokenResponseBody<T> {
    pub fn new(status: NTStatus, token_content: T::Item) -> Self {
        let state = Some(match status {
            NTStatus::StatusSuccess => NegotiateState::AcceptCompleted,
            NTStatus::SecIContinueNeeded => NegotiateState::AcceptIncomplete,
            _ => NegotiateState::Reject
        });
        Self {
            mechanism: None,
            state,
            supported_mech: Some(T::get_oid()),
            response_token: Some(token_content.as_byte_vec()),
            mech_list_mic: None,
        }
    }
}

impl<T: AuthProvider> SPNEGOTokenResponseBody<T> {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let seq_len = self.token_fields_len();
        let seq_len_field_size = get_field_size(seq_len);
        let construction_len = 1 + seq_len_field_size + seq_len;

        bytes.push(NEG_TOKEN_RESP_TAG);
        bytes.append(&mut get_length(construction_len));

        bytes.push(DER_ENCODING_SEQUENCE_TAG);
        bytes.append(&mut get_length(seq_len));

        if let Some(state) = &self.state {
            bytes.append(&mut self.negotiate_state_bytes(state));
        }

        if let Some(supported_mech) = &self.supported_mech {
            bytes.append(&mut encode_der_bytes(supported_mech, SUPPORTED_MECH_TAG, DER_ENCODING_OID_TAG, 0));
        }

        if let Some(response_token) = &self.response_token {
            bytes.append(&mut encode_der_bytes(response_token, RESPONSE_TOKEN_TAG, DER_ENCODING_BYTE_ARRAY_TAG, 0));
        }

        if let Some(mech_list_mic) = &self.mech_list_mic {
            bytes.append(&mut encode_der_bytes(mech_list_mic, MECH_LIST_MIC_TAG, DER_ENCODING_BYTE_ARRAY_TAG, 0));
        }

        bytes
    }

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (remaining, _) = parse_length(bytes)?;
        let (remaining, mut tag) = le_u8(remaining)?;
        if tag != DER_ENCODING_SEQUENCE_TAG { return Err(Error(nom::error::Error::new(remaining, ErrorKind::Fail))) }
        let (remaining, mut sequence) = parse_field_with_len(remaining)?;
        let mut state = None;
        let mut supported_mech = None;
        let mut response_token = None;
        let mut mech_list_mic = None;

        while !sequence.is_empty() {
            println!("SEQ: {:?}", sequence);
            (sequence, tag) = le_u8(sequence)?;
            match tag {
                NEG_STATE_TAG => {
                    let (s, neg_state) = Self::parse_negotiate_state(sequence)?;
                    sequence = s;
                    state = Some(neg_state);
                },
                SUPPORTED_MECH_TAG => {
                    let (s, mech) = Self::parse_supported_mech(sequence)?;
                    sequence = s;
                    supported_mech = Some(mech);
                },
                RESPONSE_TOKEN_TAG => {
                    let (s, resp) = Self::parse_response_token(sequence)?;
                    sequence = s;
                    response_token = Some(resp);
                },
                MECH_LIST_MIC_TAG => {
                    let (s, mic) = Self::parse_mech_list_mic(sequence)?;
                    sequence = s;
                    mech_list_mic = Some(mic);
                },
                _ => return Err(Error(nom::error::Error::new(remaining, ErrorKind::Fail))),
            }
        }

        Ok((remaining, SPNEGOTokenResponseBody { mechanism: None, state, supported_mech, response_token, mech_list_mic }))
    }
}

// Private static helper methods
impl<T: AuthProvider> SPNEGOTokenResponseBody<T> {
    fn parse_negotiate_state(buffer: &[u8]) -> IResult<&[u8], NegotiateState> {
        let (remaining, _) = parse_length(buffer)?;
        let (remaining, tag) = le_u8(remaining)?;
        if tag != DER_ENCODING_ENUM_TAG { return Err(Error(nom::error::Error::new(remaining, ErrorKind::Fail))) }
        map_res(le_u8, NegotiateState::try_from)(remaining)
    }

    fn parse_supported_mech(buffer: &[u8]) -> IResult<&[u8], Vec<u8>> {
        parse_der_oid(buffer)
    }

    fn parse_response_token(buffer: &[u8]) -> IResult<&[u8], Vec<u8>> {
        parse_der_byte_array(buffer)
    }

    fn parse_mech_list_mic(buffer: &[u8]) -> IResult<&[u8], Vec<u8>> {
        parse_der_byte_array(buffer)
    }
}

// Private instance helper methods (writing)
impl<T: AuthProvider> SPNEGOTokenResponseBody<T> {
    fn negotiate_state_bytes(&self, state: &NegotiateState) -> Vec<u8> {
        [
            &[NEG_STATE_TAG][0..],
            &*get_length(3),
            &[DER_ENCODING_ENUM_TAG],
            &*get_length(1),
            &[*state as u8]
        ].concat()
    }

    fn supported_mech_bytes(&self, supported_mech: &[u8]) -> Vec<u8> {
        let construction_len = 1 + get_field_size(supported_mech.len()) + supported_mech.len();
        [
            &[SUPPORTED_MECH_TAG][0..],
            &*get_length(construction_len),
            &[DER_ENCODING_OID_TAG],
            &*get_length(supported_mech.len()),
            supported_mech
        ].concat()
    }

    fn response_token_bytes(&self, response_token: &[u8]) -> Vec<u8> {
        let construction_len = 1 + get_field_size(response_token.len()) + response_token.len();
        [
            &[RESPONSE_TOKEN_TAG][0..],
            &*get_length(construction_len),
            &[DER_ENCODING_BYTE_ARRAY_TAG],
            &*get_length(response_token.len()),
            response_token
        ].concat()
    }


    fn token_fields_len(&self) -> usize {
        let mut len = 0;
        if self.state.is_some() {
            let neg_state_len = 5;
            len += neg_state_len;
        }
        if let Some(supported_mech) = &self.supported_mech {
            len += get_array_field_len(supported_mech);
        }
        if let Some(response_token) = &self.response_token {
            len += get_array_field_len(response_token);
        }
        if let Some(mech_list_mic) = &self.mech_list_mic {
            len += get_array_field_len(mech_list_mic);
        }
        len
    }
}