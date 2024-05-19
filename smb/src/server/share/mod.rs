use std::fmt::Debug;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use smb_core::SMBResult;

use crate::protocol::body::create::disposition::SMBCreateDisposition;
use crate::protocol::body::tree_connect::access_mask::SMBAccessMask;
use crate::protocol::body::tree_connect::flags::SMBShareFlags;
use crate::protocol::body::tree_connect::SMBShareType;

pub mod file_system;
pub trait ResourceHandle {
    fn close(self: Box<Self>) -> SMBResult<()>;
    fn is_directory(&self) -> bool;
}

pub trait SharedResource: Debug + Send + Sync {
    type UserName: Send + Sync;
    fn name(&self) -> &str;
    fn resource_type(&self) -> ResourceType;
    fn flags(&self) -> SMBShareFlags;
    fn handle_create(&self, path: &str, disposition: SMBCreateDisposition) -> SMBResult<Box<dyn ResourceHandle>>;
    fn close(&self, handle: Box<dyn ResourceHandle>) -> SMBResult<()> {
        handle.close()
    }
    fn connect_allowed(&self, uid: &Self::UserName) -> bool;

    fn resource_perms(&self, uid: &Self::UserName) -> SMBAccessMask;
}

impl<T: ?Sized + SharedResource> SharedResource for Box<T> {
    type UserName = T::UserName;

    fn name(&self) -> &str {
        T::name(self)
    }

    fn resource_type(&self) -> ResourceType {
        T::resource_type(self)
    }

    fn flags(&self) -> SMBShareFlags {
        T::flags(self)
    }

    fn handle_create(&self, path: &str, disposition: SMBCreateDisposition) -> SMBResult<Box<dyn ResourceHandle>> {
        T::handle_create(self, path, disposition)
    }

    fn close(&self, handle: Box<dyn ResourceHandle>) -> SMBResult<()> {
        T::close(self, handle)
    }

    fn connect_allowed(&self, uid: &Self::UserName) -> bool {
        T::connect_allowed(self, uid)
    }

    fn resource_perms(&self, uid: &Self::UserName) -> SMBAccessMask {
        T::resource_perms(self, uid)
    }
}

bitflags! {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Default, Copy, Clone)]
    pub struct ResourceType: u32 {
        const DISK = 0x0;
        const PRINT_QUEUE = 0x1;
        const DEVICE = 0x2;
        const IPC = 0x3;
        const ClusterFS = 0x02000000;
        const ClusterSOFS = 0x04000000;
        const ClusterDFS = 0x08000000;

        const SPECIAL = 0x80000000;
        const TEMPORARY = 0x40000000;
    }
}
impl From<SMBShareType> for ResourceType {
    fn from(value: SMBShareType) -> Self {
        match value {
            SMBShareType::Disk => ResourceType::DISK,
            SMBShareType::Pipe => ResourceType::IPC,
            SMBShareType::Print => ResourceType::PRINT_QUEUE
        }
    }
}