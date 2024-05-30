use std::future::Future;
use std::sync::Arc;

use tokio::sync::RwLock;

use smb_core::error::SMBError;
use smb_core::SMBResult;

pub trait SafeLockedGetter {
    type Upper;
    fn upper(&self) -> impl Future<Output=SMBResult<Arc<RwLock<Self::Upper>>>>;
}

pub trait InnerGetter {
    type Upper;
    fn upper(&self) -> Option<Arc<RwLock<Self::Upper>>>;
}

impl<Inner: InnerGetter> SafeLockedGetter for Arc<RwLock<Inner>> {
    type Upper = Inner::Upper;

    async fn upper(&self) -> SMBResult<Arc<RwLock<Self::Upper>>> {
        self.read().await.upper()
            .ok_or(SMBError::server_error("No server available"))
    }
}