use std::fmt::Debug;
use std::sync::{Arc, Weak};

use tokio::sync::RwLock;

use crate::protocol::body::filetime::FileTime;
use crate::protocol::body::tree_connect::access_mask::SMBAccessMask;
use crate::server::connection::Connection;
use crate::server::Server;
use crate::server::session::SMBSession;
use crate::server::share::SharedResource;

pub struct SMBTreeConnect<T: SharedResource, C: Connection, S: Server> {
    tree_id: u32,
    session: Weak<RwLock<SMBSession<C, S>>>,
    share: Arc<T>,
    open_count: u64,
    // tree_global_id: u64,
    creation_time: FileTime,
    maximal_access: SMBAccessMask,
    remoted_identity_security_context: Vec<u8> // TODO
}

impl<T: SharedResource, C: Connection, S: Server> SMBTreeConnect<T, C, S> {
    pub fn init(tree_id: u32, session: Weak<RwLock<SMBSession<C, S>>>, share: Arc<T>, maximal_access: SMBAccessMask) -> SMBTreeConnect<T, C, S> {
        Self {
            tree_id,
            session,
            share,
            open_count: 0,
            creation_time: FileTime::now(),
            maximal_access,
            remoted_identity_security_context: vec![],
        }
    }
}