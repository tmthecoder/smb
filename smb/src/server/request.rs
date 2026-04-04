use crate::server::Server;
use crate::server::open::SMBOpen;

pub trait Request: Send + Sync {}

pub struct SMBRequest<S: Server> {
    message_id: u64,
    async_id: u64,
    cancel_request_id: u64,
    open: SMBOpen<S>,
    is_encrypted: bool,
    transform_session_id: u64,
    compress_reply: bool,
}
