use std::fmt::Debug;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::protocol::body::tree_connect::flags::SMBShareFlags;
use crate::protocol::body::tree_connect::SMBShareType;
use crate::server::connection::Connection;
use crate::server::Server;

pub mod file_system;

pub trait ResourceHandle {}

pub trait SharedResource: Debug + Send + Sync {
    fn name(&self) -> &str;
    fn resource_type(&self) -> ResourceType;
    fn flags(&self) -> SMBShareFlags;

    fn open(&self, path: &str) -> Box<dyn ResourceHandle>;
}

impl<T: ?Sized + SharedResource> SharedResource for Box<T> {
    fn name(&self) -> &str {
        T::name(self)
    }

    fn resource_type(&self) -> ResourceType {
        T::resource_type(self)
    }

    fn flags(&self) -> SMBShareFlags {
        T::flags(self)
    }

    fn open(&self, path: &str) -> Box<dyn ResourceHandle> {
        T::open(self, path)
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