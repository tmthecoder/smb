use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct NTLMAuthenticateMessageBody {
    signature: String,
    target_name: String,
}

impl NTLMAuthenticateMessageBody {
    pub fn from_bytes(bytes: &[u8]) -> Option<NTLMAuthenticateMessageBody> {
        todo!()
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        Vec::new()
    }
}