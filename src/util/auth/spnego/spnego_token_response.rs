use nom::combinator::map_res;
use nom::Err::Error;
use nom::error::ErrorKind;
use nom::IResult;
use nom::number::complete::le_u8;
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use crate::util::auth::AuthProvider;
use crate::util::auth::spnego::util::{DER_ENCODING_ENUM_TAG, DER_ENCODING_SEQUENCE_TAG, MECH_LIST_MIC_TAG, NEG_STATE_TAG, parse_der_byte_array, parse_der_oid, parse_field_with_len, parse_length, RESPONSE_TOKEN_TAG, SUPPORTED_MECH_TAG};

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
    pub fn as_bytes(&self) -> Vec<u8> { Vec::new() }

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
