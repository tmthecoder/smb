use crate::server::{SMBConnection, SMBLease, SMBSession, SMBTreeConnect};

pub struct SMBOpen {
    file_id: u32,
    file_global_id: u32,
    durable_file_id: u32,
    session: Option<SMBSession>,
    tree_connect: Option<SMBTreeConnect>,
    connection: Option<SMBConnection>,
    local_open;
    granted_access;
    oplock_level;
    oplock_state;
    oplock_timeout;
    is_durable: bool,
    durable_open_timeout;
    durable_open_scavenger_timeout;
    durable_owner;
    current_ea_index: u32,
    current_quota_index: u32,
    lock_count: u32,
    path_name: String,
    resume_key: u32,
    file_name: String,
    create_options;
    file_attributes;
    client_guid: Vec<u8>,
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