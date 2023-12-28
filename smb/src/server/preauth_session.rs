#[derive(Debug, Clone)]
pub struct SMBPreauthSession {
    session_id: u64,
    preauth_integrity_hash_value: Vec<u8>
}