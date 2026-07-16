use std::any::Any;
use std::fmt::Debug;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use smb_core::SMBResult;

use crate::protocol::body::create::disposition::SMBCreateDisposition;
use crate::protocol::body::filetime::FileTime;
use crate::protocol::body::tree_connect::SMBShareType;
use crate::protocol::body::tree_connect::access_mask::SMBAccessMask;
use crate::protocol::body::tree_connect::flags::SMBShareFlags;

pub mod file_system;
pub mod ipc;

pub type ConnectAllowed<UserName> = fn(&UserName) -> bool;
pub type FilePerms<UserName> = fn(&UserName) -> SMBAccessMask;

pub trait ResourceHandle: Send + Sync {
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
    fn close(self: Box<Self>) -> SMBResult<()>;
    fn is_directory(&self) -> bool;
    fn path(&self) -> &str;
    fn metadata(&self) -> SMBResult<SMBFileMetadata>;
    fn read_data(&mut self, offset: u64, length: u32) -> SMBResult<Vec<u8>>;
    fn write_data(&mut self, offset: u64, data: &[u8]) -> SMBResult<u32>;
}

pub struct SMBFileMetadata {
    creation_time: FileTime,
    last_access_time: FileTime,
    last_write_time: FileTime,
    last_modification_time: FileTime,
    allocated_size: u64,
    actual_size: u64,
}

impl SMBFileMetadata {
    pub fn new(
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        last_modification_time: FileTime,
        allocated_size: u64,
        actual_size: u64,
    ) -> Self {
        Self {
            creation_time,
            last_access_time,
            last_write_time,
            last_modification_time,
            allocated_size,
            actual_size,
        }
    }

    pub fn creation_time(&self) -> &FileTime {
        &self.creation_time
    }

    pub fn last_access_time(&self) -> &FileTime {
        &self.last_access_time
    }

    pub fn last_write_time(&self) -> &FileTime {
        &self.last_write_time
    }

    pub fn last_modification_time(&self) -> &FileTime {
        &self.last_modification_time
    }

    pub fn allocated_size(&self) -> u64 {
        self.allocated_size
    }

    pub fn actual_size(&self) -> u64 {
        self.actual_size
    }
}

impl<H: ?Sized + ResourceHandle + 'static> ResourceHandle for Box<H> {
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }

    fn close(self: Box<Self>) -> SMBResult<()> {
        H::close(*self)
    }

    fn is_directory(&self) -> bool {
        H::is_directory(self)
    }

    fn path(&self) -> &str {
        H::path(self)
    }

    fn metadata(&self) -> SMBResult<SMBFileMetadata> {
        H::metadata(self)
    }

    fn read_data(&mut self, offset: u64, length: u32) -> SMBResult<Vec<u8>> {
        H::read_data(self, offset, length)
    }

    fn write_data(&mut self, offset: u64, data: &[u8]) -> SMBResult<u32> {
        H::write_data(self, offset, data)
    }
}

pub trait SharedResource: Send + Sync {
    type UserName: Send + Sync;
    type Handle: ResourceHandle;
    fn name(&self) -> &str;
    fn resource_type(&self) -> ResourceType;
    fn flags(&self) -> SMBShareFlags;
    fn handle_create(
        &self,
        path: &str,
        disposition: SMBCreateDisposition,
        directory: bool,
    ) -> SMBResult<Self::Handle>;
    fn close(&self, handle: Self::Handle) -> SMBResult<()> {
        Box::new(handle).close()
    }
    fn connect_allowed(&self, uid: &Self::UserName) -> bool;

    fn resource_perms(&self, uid: &Self::UserName) -> SMBAccessMask;
}

impl<T: ?Sized + SharedResource> SharedResource for Box<T> {
    type UserName = T::UserName;
    type Handle = T::Handle;

    fn name(&self) -> &str {
        T::name(self)
    }

    fn resource_type(&self) -> ResourceType {
        T::resource_type(self)
    }

    fn flags(&self) -> SMBShareFlags {
        T::flags(self)
    }

    fn handle_create(
        &self,
        path: &str,
        disposition: SMBCreateDisposition,
        directory: bool,
    ) -> SMBResult<Self::Handle> {
        T::handle_create(self, path, disposition, directory)
    }

    fn close(&self, handle: Self::Handle) -> SMBResult<()> {
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
            SMBShareType::Print => ResourceType::PRINT_QUEUE,
        }
    }
}
