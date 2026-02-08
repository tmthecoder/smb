use std::fmt::Debug;
use std::ops::Deref;
use std::sync::{Arc, Weak};

use tokio::sync::RwLock;

use smb_core::{SMBByteSize, SMBResult};
use smb_core::error::SMBError;
use smb_core::logging::{debug, trace};

use crate::protocol::body::create::{SMBCreateRequest, SMBCreateResponse};
use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::filetime::FileTime;
use crate::protocol::body::SMBBody;
use crate::protocol::body::tree_connect::access_mask::SMBAccessMask;
use crate::protocol::header::SMBSyncHeader;
use crate::protocol::message::SMBMessage;
use crate::server::message_handler::{SMBHandlerState, SMBLockedMessageHandler, SMBLockedMessageHandlerBase, SMBMessageType};
use crate::server::open::{Open, SMBOpen};
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
    remoted_identity_security_context: Vec<u8>, // TODO
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
    type Inner = Arc<SMBOpen<S>>;

    async fn inner(&self, message: &SMBMessageType) -> Option<Self::Inner> {
        None
    }

    async fn handle_create(&mut self, header: &SMBSyncHeader, message: &SMBCreateRequest) -> SMBResult<SMBHandlerState<Self::Inner>> {
        let (path, disposition, directory) = message.validate(self.share.deref())?;
        let handle = self.share.handle_create(path, disposition, directory)?;
        let open_raw = Open::init(handle, message);
        let response = SMBBody::CreateResponse(SMBCreateResponse::for_open::<S>(&open_raw)?);
        let open = Arc::new(RwLock::new(open_raw));
        let session = self.session.upgrade()
            .ok_or(SMBError::server_error("No Session Found"))?;
        session.write().await.add_open(open.clone()).await;
        let server = session.upper().await?
            .upper().await?;
        {
            server.write().await.add_open(open.clone()).await;
        }
        {
            let file_id = open.read().await.file_id();
            session.write().await.set_previous_file_id(file_id);
        }
        debug!("tree connect create handled");
        let header = header.create_response_header(header.channel_sequence, header.session_id, header.tree_id);
        trace!(response_size = response.smb_byte_size(), "create response built");
        Ok(SMBHandlerState::Finished(SMBMessage::new(header, response)))
    }
}

impl<S: Server> SMBLockedMessageHandler for Arc<SMBTreeConnect<S>> {}