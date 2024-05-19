use std::fmt::Debug;

use crate::server::connection::Connection;
use crate::server::open::SMBOpen;
use crate::server::Server;

pub trait Request: Debug + Send + Sync {}

pub struct SMBRequest<C: Connection, S: Server> {
    message_id: u64,
    async_id: u64,
    cancel_request_id: u64,
    open: SMBOpen<C, S>,
    is_encrypted: bool,
    transform_session_id: u64,
    compress_reply: bool
}