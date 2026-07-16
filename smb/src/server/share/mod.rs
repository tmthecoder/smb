use std::any::Any;
use std::fmt::Debug;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use smb_core::SMBResult;

use crate::protocol::body::create::disposition::SMBCreateDisposition;
use crate::protocol::body::create::file_attributes::SMBFileAttributes;
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
    /// Return the directory entries matching `pattern` that have not yet been
    /// consumed by this enumeration (MS-SMB2 §3.3.5.18). A fresh scan is taken
    /// when `restart` is set or no enumeration has been started; a fresh scan
    /// matching nothing fails with `STATUS_NO_SUCH_FILE`. Entries are only
    /// removed from the enumeration via `consume_directory_entries`.
    fn query_directory(
        &mut self,
        pattern: &str,
        restart: bool,
    ) -> SMBResult<Vec<SMBDirectoryEntry>>;
    /// Advance the enumeration past `count` entries previously returned by
    /// `query_directory`, so they are not returned again.
    fn consume_directory_entries(&mut self, count: usize);
}

/// A single directory entry produced by [`ResourceHandle::query_directory`],
/// carrying everything needed to build the MS-FSCC directory information
/// classes returned by QueryDirectory.
#[derive(Debug, Clone)]
pub struct SMBDirectoryEntry {
    name: String,
    metadata: SMBFileMetadata,
    attributes: SMBFileAttributes,
    file_id: u64,
}

impl SMBDirectoryEntry {
    pub fn new(
        name: String,
        metadata: SMBFileMetadata,
        attributes: SMBFileAttributes,
        file_id: u64,
    ) -> Self {
        Self {
            name,
            metadata,
            attributes,
            file_id,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn metadata(&self) -> &SMBFileMetadata {
        &self.metadata
    }

    pub fn attributes(&self) -> SMBFileAttributes {
        self.attributes
    }

    pub fn file_id(&self) -> u64 {
        self.file_id
    }
}

#[derive(Debug, Clone)]
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

    fn query_directory(
        &mut self,
        pattern: &str,
        restart: bool,
    ) -> SMBResult<Vec<SMBDirectoryEntry>> {
        H::query_directory(self, pattern, restart)
    }

    fn consume_directory_entries(&mut self, count: usize) {
        H::consume_directory_entries(self, count)
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
