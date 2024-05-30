use std::fmt::Debug;
use std::ops::Deref;
use std::sync::{Arc, Weak};

use tokio::sync::RwLock;

use smb_core::error::SMBError;
use smb_core::SMBResult;

use crate::protocol::body::create::SMBCreateRequest;
use crate::protocol::body::filetime::FileTime;
use crate::protocol::body::tree_connect::access_mask::SMBAccessMask;
use crate::protocol::header::SMBSyncHeader;
use crate::server::connection::Connection;
use crate::server::message_handler::{SMBHandlerState, SMBLockedMessageHandler, SMBLockedMessageHandlerBase, SMBMessageType};
use crate::server::open::Open;
use crate::server::safe_locked_getter::SafeLockedGetter;
use crate::server::Server;
use crate::server::session::Session;
use crate::server::share::SharedResource;

#[derive(Debug)]
pub struct SMBTreeConnect<S: Server> {
    tree_id: u32,
    session: Weak<RwLock<S::Session>>,
    share: Arc<S::Share>,
    open_count: u64,
    // tree_global_id: u64,
    creation_time: FileTime,
    maximal_access: SMBAccessMask,
    remoted_identity_security_context: Vec<u8> // TODO
}

impl<S: Server> SMBTreeConnect<S> {
    pub fn init(tree_id: u32, session: Weak<RwLock<S::Session>>, share: Arc<S::Share>, maximal_access: SMBAccessMask) -> SMBTreeConnect<S> {
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

impl<S: Server> SMBLockedMessageHandlerBase for Arc<SMBTreeConnect<S>> {
    type Inner = ();

    async fn inner(&self, message: &SMBMessageType) -> Option<Self::Inner> {
        Some(())
    }

    async fn handle_create(&mut self, header: &SMBSyncHeader, message: &SMBCreateRequest) -> SMBResult<SMBHandlerState<Self::Inner>> {
        let (path, disposition, directory) = message.validate(self.share.deref())?;
        let handle = self.share.handle_create(path, disposition, directory)?;
        let open = Arc::new(RwLock::new(S::Open::init(handle)));
        let session = self.session.upgrade()
            .ok_or(SMBError::server_error("No Session Found"))?;
        session.write().await.add_open(open.clone()).await;
        let server = session.upper()
            .await?
            .upper()
            .await?;
        server.write().await.add_open(open).await;
        println!("In tree connect create");
        todo!("Need to create an open to finish create handler")
    }
}

impl<S: Server> SMBLockedMessageHandler for Arc<SMBTreeConnect<S>> {}