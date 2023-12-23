use std::fmt::Debug;

use crate::server::share::SharedResource;
use crate::server::SMBOpen;

pub trait Request: Debug + Send + Sync {}
pub struct SMBRequest<T: SharedResource> {
    message_id: u64,
    async_id: u64,
    cancel_request_id: u64,
    open: SMBOpen<T>,
    is_encrypted: bool,
    transform_session_id: u64,
    compress_reply: bool
}