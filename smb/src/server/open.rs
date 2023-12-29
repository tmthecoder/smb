use std::fmt::Debug;
use std::fs::File;

use uuid::Uuid;

use crate::protocol::body::create::options::SMBCreateOptions;
use crate::protocol::body::tree_connect::access_mask::SMBAccessMask;
use crate::server::connection::SMBConnection;
use crate::server::lease::SMBLease;
use crate::server::Server;
use crate::server::session::SMBSession;
use crate::server::share::SharedResource;
use crate::server::tree_connect::SMBTreeConnect;
use crate::socket::message_stream::{SMBReadStream, SMBWriteStream};

pub trait Open: Debug + Send + Sync {}

pub struct SMBOpen<T: SharedResource, R: SMBReadStream, W: SMBWriteStream, S: Server> {
    file_id: u32,
    file_global_id: u32,
    durable_file_id: u32,
    session: Option<SMBSession<R, W, S>>,
    tree_connect: Option<SMBTreeConnect<T, R, W, S>>,
    connection: Option<SMBConnection<R, W, S>>,
    local_open: File,
    // TODO make this an interface for different open types
    granted_access: SMBAccessMask,
    oplock_level: SMBOplockLevel,
    oplock_state: SMBOplockState,
    oplock_timeout: u64,
    is_durable: bool,
    durable_open_timeout: u64,
    durable_open_scavenger_timeout: u64,
    durable_owner: u64,
    // TODO
    current_ea_index: u32,
    current_quota_index: u32,
    lock_count: u32,
    path_name: String,
    resume_key: u32,
    file_name: String,
    create_options: SMBCreateOptions,
    file_attributes: FileAttributes,
    client_guid: Uuid,
    lease: Option<SMBLease>,
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

// TODO: From MS-FSCC section 2.6
struct FileAttributes;

pub enum SMBOplockLevel {
    None,
    II,
    Exclusive,
    Batch,
    Lease
}

pub enum SMBOplockState {
    Held,
    Breaking,
    None
}

pub struct LockSequence {
    sequence_number: u32,
    valid: bool,
}