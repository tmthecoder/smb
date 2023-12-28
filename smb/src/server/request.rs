use std::fmt::Debug;

use crate::server::open::SMBOpen;
use crate::server::Server;
use crate::server::share::SharedResource;
use crate::socket::message_stream::{SMBReadStream, SMBWriteStream};

pub trait Request: Debug + Send + Sync {}

pub struct SMBRequest<T: SharedResource, R: SMBReadStream, W: SMBWriteStream, S: Server> {
    message_id: u64,
    async_id: u64,
    cancel_request_id: u64,
    open: SMBOpen<T, R, W, S>,
    is_encrypted: bool,
    transform_session_id: u64,
    compress_reply: bool
}