#[derive(Debug, Clone)]
pub struct SMBPreauthSession {
    session_id: u64,
    preauth_integrity_hash_value: Vec<u8>
}

impl SMBPreauthSession {
    pub fn new(session_id: u64, preauth_integrity_hash_value: Vec<u8>) -> Self {
        Self {
            session_id,
            preauth_integrity_hash_value,
        }
    }
}