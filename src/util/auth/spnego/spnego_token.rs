use serde::{Deserialize, Serialize};
use crate::util::auth::AuthProvider;
use crate::util::auth::spnego::{SPNEGOTokenInit2Body, SPNEGOTokenInitBody, SPNEGOTokenResponseBody};
use crate::util::auth::spnego::util::{DER_ENCODING_OID_TAG, read_length, SPNEGO_ID, NEG_TOKEN_INIT_TAG, NEG_TOKEN_RESP_TAG, get_field_size, APPLICATION_TAG, get_length, DER_ENCODING_SEQUENCE_TAG};

#[derive(Debug, Deserialize, Serialize)]
pub enum SPNEGOToken<T: AuthProvider> {
    Init(SPNEGOTokenInitBody<T>),
    Init2(SPNEGOTokenInit2Body<T>),
    Response(SPNEGOTokenResponseBody<T>),
}

impl<T: AuthProvider> SPNEGOToken<T> {
    pub fn from_bytes(bytes: &[u8], offset: &mut usize) -> Option<Self> {
        println!("off: {}, Bytesss: {:?}", offset, bytes);
        let tag = bytes[*offset];
        *offset += 1;
        match tag {
            APPLICATION_TAG => {
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
                None
            },
            NEG_TOKEN_RESP_TAG => Some(SPNEGOToken::Response(SPNEGOTokenResponseBody::from_bytes(bytes, offset)?)),
            _ => None,
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