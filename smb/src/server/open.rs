use std::fmt::Debug;

use uuid::Uuid;

use crate::protocol::body::create::oplock::SMBOplockLevel;
use crate::protocol::body::create::options::SMBCreateOptions;
use crate::protocol::body::tree_connect::access_mask::SMBAccessMask;
use crate::server::connection::Connection;
use crate::server::lease::SMBLease;
use crate::server::Server;
use crate::server::session::SMBSession;
use crate::server::share::ResourceHandle;
use crate::server::tree_connect::SMBTreeConnect;

pub trait Open: Send + Sync {
    fn file_name(&self) -> &str;
}

pub trait DebuggableHandle: ResourceHandle + Debug {}

#[derive(Debug)]
pub struct SMBOpen<C: Connection, S: Server> {
    file_id: u32,
    file_global_id: u32,
    durable_file_id: u32,
    session: Option<SMBSession<C, S>>,
    tree_connect: Option<SMBTreeConnect<C, S>>,
    connection: Option<C>,
    granted_access: SMBAccessMask,
    oplock_level: SMBOplockLevel,
    oplock_state: SMBOplockState,
    oplock_timeout: u64,
    is_durable: bool,
    durable_open_timeout: u64,
    durable_open_scavenger_timeout: u64,
    durable_owner: u64,
    underlying: Box<dyn DebuggableHandle>,
    current_ea_index: u32,
    current_quota_index: u32,
    lock_count: u32,
    path_name: String,
    resume_key: u32,
    file_name: String,
    create_options: SMBCreateOptions,
    file_attributes: FileAttributes,
    client_guid: Uuid,
    lease: Option<SMBLease<C, S>>,
    is_resilient: bool,
    resiliency_timeout: u32,
    resilient_open_timeout: u32,
    lock_sequence_array: Vec<LockSequence>,
    create_guid: u128,
    app_instance_id: u128,
    is_persistent: bool,
    channel_sequence: u128,
    outstanding_request_count: u32,
    outstanding_pre_request_count: u32,
    is_shared_vhdx: bool,
    application_instance_version_high: u64,
    application_instance_version_low: u64,
}

impl<C: Connection, S: Server> Open for SMBOpen<C, S> {
    fn file_name(&self) -> &str {
        &self.file_name
    }
}
// TODO: From MS-FSCC section 2.6
#[derive(Debug)]
struct FileAttributes;

#[derive(Debug)]
pub enum SMBOplockState {
    Held,
    Breaking,
    None
}

#[derive(Debug)]
pub struct LockSequence {
    sequence_number: u32,
    valid: bool,
}