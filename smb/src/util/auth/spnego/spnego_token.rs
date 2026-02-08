use nom::bytes::complete::take;
use nom::Err::Error;
use nom::error::ErrorKind;
use nom::IResult;
use nom::number::complete::le_u8;
use serde::{Deserialize, Serialize};

use smb_core::{SMBParseResult, SMBResult};
use smb_core::error::SMBError;
use smb_core::nt_status::NTStatus;

use crate::util::auth::{AuthMessage, AuthProvider};
use crate::util::auth::spnego::{SPNEGOTokenInit2Body, SPNEGOTokenInitBody, SPNEGOTokenResponseBody};
use crate::util::auth::spnego::der_utils::{APPLICATION_TAG, DER_ENCODING_OID_TAG, get_field_size, get_length, NEG_TOKEN_INIT_TAG, NEG_TOKEN_RESP_TAG, parse_field_with_len, SPNEGO_ID};

#[derive(Debug, Deserialize, Serialize)]
pub enum SPNEGOToken<A: AuthProvider> {
    Init(SPNEGOTokenInitBody<A>),
    Init2(SPNEGOTokenInit2Body<A>),
    Response(SPNEGOTokenResponseBody<A>),
}

impl<A: AuthProvider> SPNEGOToken<A> {
    pub fn get_message(&self, auth_provider: &A, ctx: &mut A::Context) -> SMBResult<(NTStatus, A::Message)> {
        let result = match self {
            SPNEGOToken::Init(init_msg) => {
                let mech_token = init_msg.mech_token.as_ref().ok_or(SMBError::parse_error("Parse failure"))?;
                let ntlm_msg =
                    A::Message::parse(mech_token).map_err(|_e| SMBError::parse_error("Parse failure"))?.1;
                auth_provider.accept_security_context(&ntlm_msg, ctx)
            }
            SPNEGOToken::Response(resp_msg) => {
                let response_token = resp_msg.response_token.as_ref().ok_or(SMBError::parse_error("Parse failure"))?;
                let ntlm_msg =
                    A::Message::parse(response_token).map_err(|_e| SMBError::parse_error("Parse failure"))?.1;
                auth_provider.accept_security_context(&ntlm_msg, ctx)
            }
            _ => { (NTStatus::StatusSuccess, A::Message::empty()) }
        };

        Ok(result)
    }
    pub fn parse(bytes: &[u8]) -> SMBParseResult<&[u8], Self> {
        Self::parse_inner(bytes).map_err(|e| SMBError::parse_error(e.to_owned()))
    }
    fn parse_inner(bytes: &[u8]) -> IResult<&[u8], Self> {
        smb_core::logging::trace!(buf_len = bytes.len(), "parsing SPNEGO token");
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
                        smb_core::logging::trace!(tag, "SPNEGO inner tag");
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