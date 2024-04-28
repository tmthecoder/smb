use std::future::Future;
use std::sync::Arc;

use tokio::sync::RwLock;

use smb_core::error::SMBError;
use smb_core::SMBResult;

use crate::server::Server;

pub trait SafeLockedGetter<S> {
    fn server(&self) -> impl Future<Output=SMBResult<Arc<RwLock<S>>>>;
}

pub trait InnerGetter<S> {
    fn server(&self) -> Option<Arc<RwLock<S>>>;
}

impl<S: Server, Inner: InnerGetter<S>> SafeLockedGetter<S> for Arc<RwLock<Inner>> {
    async fn server(&self) -> SMBResult<Arc<RwLock<S>>> {
        self.read().await.server()
            .ok_or(SMBError::server_error("No server available"))
    }
}