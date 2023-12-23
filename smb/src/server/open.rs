use std::fmt::Debug;
use std::fs::File;

use uuid::Uuid;

use crate::protocol::body::create::SMBCreateOptions;
use crate::protocol::body::tree_connect::SMBAccessMask;
use crate::server::{SMBConnection, SMBLease, SMBSession, SMBTreeConnect};
use crate::server::share::SharedResource;

pub trait Open: Debug {}

pub struct SMBOpen<T: SharedResource> {
    file_id: u32,
    file_global_id: u32,
    durable_file_id: u32,
    session: Option<SMBSession<T>>,
    tree_connect: Option<SMBTreeConnect<T>>,
    connection: Option<SMBConnection>,
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