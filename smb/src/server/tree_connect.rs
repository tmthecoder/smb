use std::fmt::Debug;

use crate::protocol::body::filetime::FileTime;
use crate::protocol::body::tree_connect::access_mask::SMBAccessMask;
use crate::server::connection::Connection;
use crate::server::Server;
use crate::server::session::SMBSession;
use crate::server::share::SharedResource;

pub trait TreeConnect: Debug + Send + Sync {}

pub struct SMBTreeConnect<T: SharedResource, C: Connection, S: Server> {
    tree_id: u32,
    session: SMBSession<C, S>,
    share: T,
    open_count: u64,
    tree_global_id: u64,
    creation_time: FileTime,
    maximal_access: SMBAccessMask,
    remoted_identity_security_context: Vec<u8> // TODO
}