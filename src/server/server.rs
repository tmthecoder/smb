use std::collections::HashMap;
use uuid::Uuid;
use crate::body::{FileTime, SMBDialect};
use crate::server::{SMBClient, SMBConnection, SMBLeaseTable, SMBOpen, SMBSession, SMBShare};

pub struct SMBServer {
    statistics: ServerDiagnostics,
    enabled: bool,
    share_list: HashMap<(String, String), SMBShare>,
    open_table: HashMap<u64, SMBOpen>,
    session_table: HashMap<u64, SMBSession>,
    connection_list: HashMap<u64, SMBConnection>,
    guid: Uuid,
    start_time: FileTime,
    dfs_capable: bool,
    copy_max_chunks: u64,
    copy_max_chunk_size: u64,
    copy_max_data_size: u64,
    hash_level: HashLevel,
    lease_table_list: HashMap<Uuid, SMBLeaseTable>,
    max_resiliency_timeout: u64, // TODO ?
    resilient_open_scavenger_expiry_time: u64, // TODO ?
    client_table: HashMap<Uuid, SMBClient>,
    encrypt_data: bool,
    reject_unencrypted_access: bool,
    multi_channel_capable: bool,
    allow_anonymous_access: bool,
    shared_vhd_supported: bool,
    max_cluster_dialect: SMBDialect,
    supports_tree_connection: bool,
    allow_named_pipe_access_over_quic: bool,
}

pub enum HashLevel {
    EnableAll,
    DisableAll,
    EnableShare
}

impl SMBServer {

}

pub struct ServerDiagnostics {
    start: u32,
    file_opens: u32,
    device_opens: u32,
    jobs_queued: u32,
    session_opens: u32,
    session_timed_out: u32,
    session_error_out: u32,
    password_errors: u32,
    permission_errors: u32,
    system_errors: u32,
    bytes_sent: u64,
    bytes_received: u64,
    average_response: u32,
    request_buffer_need: u32,
    big_bugger_need: u32,
}