use std::marker::{PhantomData, Tuple};

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::protocol::body::tree_connect::{SMBAccessMask, SMBShareFlags, SMBShareType};

pub trait SharedResource {
    fn name(&self) -> &String;
}

#[derive(Debug)]
pub struct SMBShare<ConnectArgs: Tuple, FileSecArgs: Tuple, ConnectAllowed: Fn(ConnectArgs) -> bool, FilePerms: Fn(FileSecArgs) -> SMBAccessMask> {
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
    connect_phantom: PhantomData<ConnectArgs>,
    file_phantom: PhantomData<FileSecArgs>,
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