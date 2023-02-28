use nom::bytes::complete::take;
use nom::Err::Error;
use nom::error::ErrorKind;
use nom::IResult;
use nom::number::complete::le_u8;
use serde::{Deserialize, Serialize};

use crate::util::auth::AuthProvider;
use crate::util::auth::spnego::{SPNEGOTokenInit2Body, SPNEGOTokenInitBody, SPNEGOTokenResponseBody};
use crate::util::auth::spnego::der_utils::{APPLICATION_TAG, DER_ENCODING_OID_TAG, DER_ENCODING_SEQUENCE_TAG, get_field_size, get_length, NEG_TOKEN_INIT_TAG, NEG_TOKEN_RESP_TAG, parse_field_with_len, SPNEGO_ID};

#[derive(Debug, Deserialize, Serialize)]
pub enum SPNEGOToken<T: AuthProvider> {
    Init(SPNEGOTokenInitBody<T>),
    Init2(SPNEGOTokenInit2Body<T>),
    Response(SPNEGOTokenResponseBody<T>),
}

impl<T: AuthProvider> SPNEGOToken<T> {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        println!("bytes: {:?},", bytes);
        let (remaining, tag) = le_u8(bytes)?;
        match tag {
            APPLICATION_TAG => {
                take(1_usize)(remaining)
                    .and_then(|(remaining, _)| {
                        let (remaining, tag) = le_u8(remaining)?;
                        if tag != DER_ENCODING_OID_TAG {
                            return Err(Error(nom::error::Error::new(remaining, ErrorKind::Fail)));
                        }
                        let (remaining, oid) = parse_field_with_len(remaining)?;
                        if oid.len() != SPNEGO_ID.len() || *oid != SPNEGO_ID {
                            return Err(Error(nom::error::Error::new(remaining, ErrorKind::Fail)));
                        }
                        let (remaining, tag) = le_u8(remaining)?;
                        println!("TAG: {}", tag);
                        match tag {
                            NEG_TOKEN_INIT_TAG => {
                                let (remaining, body) = SPNEGOTokenInitBody::parse(remaining)?;
                                Ok((remaining, SPNEGOToken::Init(body)))
                            },
                            NEG_TOKEN_RESP_TAG => {
                                let (remaining, body) = SPNEGOTokenResponseBody::parse(remaining)?;
                                Ok((remaining, SPNEGOToken::Response(body)))
                            },
                            _ => Err(Error(nom::error::Error::new(remaining, ErrorKind::Fail)))
                        }
                    })
            },
            NEG_TOKEN_RESP_TAG => {
                let (remaining, body) = SPNEGOTokenResponseBody::parse(remaining)?;
                Ok((remaining, SPNEGOToken::Response(body)))
            },
            _ => Err(Error(nom::error::Error::new(remaining, ErrorKind::Fail)))
        }
    }

    pub fn as_bytes(&self, header: bool) -> Vec<u8> {
        let bytes = match self {
            SPNEGOToken::Init(x) => x.as_bytes(),
            SPNEGOToken::Init2(x) => x.as_bytes(),
            SPNEGOToken::Response(x) => x.as_bytes(),
        };
        if header {
            let oid_size = get_field_size(SPNEGO_ID.len());
            let token_len = 1 + oid_size + SPNEGO_ID.len() + bytes.len();
            [
                &[APPLICATION_TAG][0..],
                &get_length(token_len),
                &[DER_ENCODING_OID_TAG],
                &get_length(SPNEGO_ID.len()),
                &SPNEGO_ID,
                &bytes
            ].concat()
        } else {
            bytes.to_vec()
        }
    }
}