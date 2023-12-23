use std::fmt::{Debug, Formatter};

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::protocol::body::tree_connect::{SMBAccessMask, SMBShareFlags, SMBShareType};

pub trait SharedResource: Debug {
    fn name(&self) -> &str;
}

impl<ConnectAllowed: Fn(u64) -> bool, FilePerms: Fn(u64) -> SMBAccessMask> SharedResource for SMBShare<ConnectAllowed, FilePerms> {
    fn name(&self) -> &str {
        &self.name
    }
}

pub struct SMBShare<ConnectAllowed: Fn(u64) -> bool, FilePerms: Fn(u64) -> SMBAccessMask> {
    name: String,
    server_name: String,
    local_path: String,
    connect_security: ConnectAllowed,
    file_security: FilePerms,
    csc_flags: SMBShareFlags,
    dfs_enabled: bool,
    do_access_based_directory_enumeration: bool,
    allow_namespace_caching: bool,
    force_shared_delete: bool,
    restrict_exclusive_options: bool,
    share_type: ResourceType,
    remark: String,
    max_uses: u64,
    current_uses: u64,
    force_level_2_oplock: bool,
    hash_enabled: bool,
    snapshot_list: Vec<u8>,
    ca_timeout: u64,
    continuously_available: bool,
    encrypt_data: bool,
    supports_identity_remoting: bool,
    compress_data: bool,
}

impl<ConnectAllowed: Fn(u64) -> bool, FilePerms: Fn(u64) -> SMBAccessMask> Debug for SMBShare<ConnectAllowed, FilePerms> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SMBServer")
            .field("name", &self.name)
            .field("server_name", &self.server_name)
            .field("local_path", &self.local_path)
            .field("csc_flags", &self.csc_flags)
            .field("dfs_enabled", &self.dfs_enabled)
            .field("do_access_based_directory_enumeration", &self.do_access_based_directory_enumeration)
            .field("allow_namespace_caching", &self.allow_namespace_caching)
            .field("force_shared_delete", &self.force_shared_delete)
            .field("restrict_exclusive_options", &self.restrict_exclusive_options)
            .field("share_type", &self.share_type)
            .field("remark", &self.remark)
            .field("max_uses", &self.max_uses)
            .field("current_uses", &self.current_uses)
            .field("force_level_2_oplock", &self.force_level_2_oplock)
            .field("hash_enabled", &self.hash_enabled)
            .field("snapshot_list", &self.snapshot_list)
            .field("ca_timeout", &self.ca_timeout)
            .field("continuously_available", &self.continuously_available)
            .field("encrypt_data", &self.encrypt_data)
            .field("supports_identity_remoting", &self.supports_identity_remoting)
            .field("compress_data", &self.compress_data)
            .finish()
    }
}

impl<ConnectAllowed: Fn(u64) -> bool, FilePerms: Fn(u64) -> SMBAccessMask> SMBShare<ConnectAllowed, FilePerms> {
    pub fn disk(name: String, connect_security: ConnectAllowed, file_security: FilePerms) -> Self {
        Self {
            name,
            server_name: "localhost".into(),
            local_path: "/".into(),
            connect_security,
            file_security,
            csc_flags: SMBShareFlags::default(),
            dfs_enabled: false,
            do_access_based_directory_enumeration: false,
            allow_namespace_caching: false,
            force_shared_delete: false,
            restrict_exclusive_options: false,
            share_type: ResourceType::DISK,
            remark: "some share comment".into(),
            max_uses: 10,
            current_uses: 0,
            force_level_2_oplock: false,
            hash_enabled: true,
            snapshot_list: vec![],
            ca_timeout: 1000,
            continuously_available: true,
            encrypt_data: true,
            supports_identity_remoting: true,
            compress_data: false,
        }
    }
}

bitflags! {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Default)]
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