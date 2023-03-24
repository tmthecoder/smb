use crate::server::SMBOpen;

pub struct SMBRequest {
    message_id: u64,
    async_id: u64,
    cancel_request_id: u64,
    open: SMBOpen,
    is_encrypted: bool,
    transform_session_id: u64,
    compress_reply: bool
}