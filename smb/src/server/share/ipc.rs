use std::any::Any;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;

use smb_core::error::SMBError;
use smb_core::SMBResult;

use crate::protocol::body::create::disposition::SMBCreateDisposition;
use crate::protocol::body::filetime::FileTime;
use crate::protocol::body::tree_connect::access_mask::{SMBAccessMask, SMBFilePipePrinterAccessMask};
use crate::protocol::body::tree_connect::flags::SMBShareFlags;
use crate::server::share::{ResourceHandle, ResourceType, SharedResource, SMBFileMetadata};

/// A minimal IPC$ named pipe share handle
#[derive(Debug)]
pub struct SMBIPCHandle {
    path: String,
}

impl ResourceHandle for SMBIPCHandle {
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }

    fn close(self: Box<Self>) -> SMBResult<()> {
        Ok(())
    }

    fn is_directory(&self) -> bool {
        false
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn metadata(&self) -> SMBResult<SMBFileMetadata> {
        Ok(SMBFileMetadata {
            creation_time: FileTime::default(),
            last_access_time: FileTime::default(),
            last_write_time: FileTime::default(),
            last_modification_time: FileTime::default(),
            allocated_size: 0,
            actual_size: 0,
        })
    }
}

impl From<SMBIPCHandle> for Box<dyn ResourceHandle> {
    fn from(value: SMBIPCHandle) -> Self {
        Box::new(value)
    }
}

/// IPC$ pipe share — allows smbclient to connect for share enumeration
pub struct SMBIPCShare<UserName: Send + Sync, Handle: From<SMBIPCHandle> + ResourceHandle> {
    _user_name: PhantomData<UserName>,
    _handle: PhantomData<Handle>,
}

impl<UserName: Send + Sync, Handle: From<SMBIPCHandle> + ResourceHandle> SMBIPCShare<UserName, Handle> {
    pub fn new() -> Self {
        Self {
            _user_name: PhantomData,
            _handle: PhantomData,
        }
    }
}

impl<UserName: Send + Sync, Handle: From<SMBIPCHandle> + ResourceHandle> Debug for SMBIPCShare<UserName, Handle> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SMBIPCShare").finish()
    }
}

impl<UserName: Send + Sync + 'static, Handle: From<SMBIPCHandle> + ResourceHandle + 'static> From<SMBIPCShare<UserName, Handle>> for Box<dyn SharedResource<UserName=UserName, Handle=Handle>> {
    fn from(value: SMBIPCShare<UserName, Handle>) -> Self {
        Box::new(value)
    }
}

impl<UserName: Send + Sync, Handle: From<SMBIPCHandle> + ResourceHandle> SharedResource for SMBIPCShare<UserName, Handle> {
    type UserName = UserName;
    type Handle = Handle;

    fn name(&self) -> &str {
        "IPC$"
    }

    fn resource_type(&self) -> ResourceType {
        ResourceType::IPC
    }

    fn flags(&self) -> SMBShareFlags {
        SMBShareFlags::default()
    }

    fn handle_create(&self, path: &str, _disposition: SMBCreateDisposition, _directory: bool) -> SMBResult<Self::Handle> {
        let handle = SMBIPCHandle {
            path: path.to_string(),
        };
        Ok(handle.into())
    }

    fn connect_allowed(&self, _uid: &Self::UserName) -> bool {
        true
    }

    fn resource_perms(&self, _uid: &Self::UserName) -> SMBAccessMask {
        SMBAccessMask::FilePipePrinter(SMBFilePipePrinterAccessMask::all())
    }
}
