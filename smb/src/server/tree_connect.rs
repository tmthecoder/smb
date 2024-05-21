use std::fmt::Debug;
use std::ops::Deref;
use std::sync::{Arc, Weak};

use tokio::sync::RwLock;

use smb_core::SMBResult;

use crate::protocol::body::create::SMBCreateRequest;
use crate::protocol::body::filetime::FileTime;
use crate::protocol::body::tree_connect::access_mask::SMBAccessMask;
use crate::protocol::header::SMBSyncHeader;
use crate::server::connection::Connection;
use crate::server::message_handler::{SMBHandlerState, SMBLockedMessageHandler, SMBLockedMessageHandlerBase, SMBMessageType};
use crate::server::Server;
use crate::server::session::SMBSession;
use crate::server::share::SharedResource;

pub struct SMBTreeConnect<C: Connection, S: Server> {
    tree_id: u32,
    session: Weak<RwLock<SMBSession<C, S>>>,
    share: Arc<S::Share>,
    open_count: u64,
    // tree_global_id: u64,
    creation_time: FileTime,
    maximal_access: SMBAccessMask,
    remoted_identity_security_context: Vec<u8> // TODO
}

impl<C: Connection, S: Server> SMBTreeConnect<C, S> {
    pub fn init(tree_id: u32, session: Weak<RwLock<SMBSession<C, S>>>, share: Arc<S::Share>, maximal_access: SMBAccessMask) -> SMBTreeConnect<C, S> {
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

impl<C: Connection, S: Server> SMBLockedMessageHandlerBase for Arc<SMBTreeConnect<C, S>> {
    type Inner = ();

    async fn inner(&self, message: &SMBMessageType) -> Option<Self::Inner> {
        Some(())
    }

    async fn handle_create(&mut self, header: &SMBSyncHeader, message: &SMBCreateRequest) -> SMBResult<SMBHandlerState<Self::Inner>> {
        let (path, disposition, directory) = message.validate(self.share.deref())?;
        self.share.handle_create(path, disposition, directory)?;
        println!("In tree connect create");
        todo!()
    }
}

impl<C: Connection, S: Server> SMBLockedMessageHandler for Arc<SMBTreeConnect<C, S>> {}