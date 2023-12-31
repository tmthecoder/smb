use std::fmt::Debug;

use crate::server::connection::Connection;
use crate::server::open::SMBOpen;
use crate::server::Server;
use crate::server::share::SharedResource;

pub trait Request: Debug + Send + Sync {}

pub struct SMBRequest<T: SharedResource, C: Connection, S: Server> {
    message_id: u64,
    async_id: u64,
    cancel_request_id: u64,
    open: SMBOpen<T, C, S>,
    is_encrypted: bool,
    transform_session_id: u64,
    compress_reply: bool
}