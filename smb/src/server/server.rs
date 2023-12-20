use std::collections::HashMap;

use uuid::Uuid;

use crate::protocol::body::{FileTime, SMBDialect};
use crate::server::{SMBClient, SMBLeaseTable};
use crate::server::connection::Connection;
use crate::server::open::Open;
use crate::server::session::Session;
use crate::server::share::SharedResource;

#[derive(Default)]
pub struct SMBServer {
    statistics: ServerDiagnostics,
    enabled: bool,
    share_list: HashMap<String, Box<dyn SharedResource>>,
    open_table: HashMap<u64, Box<dyn Open>>,
    session_table: HashMap<u64, Box<dyn Session>>,
    connection_list: HashMap<u64, Box<dyn Connection>>,
    guid: Uuid,
    start_time: FileTime,
    dfs_capable: bool,
    copy_max_chunks: u64,
    copy_max_chunk_size: u64,
    copy_max_data_size: u64,
    hash_level: HashLevel,
    lease_table_list: HashMap<Uuid, SMBLeaseTable>,
    max_resiliency_timeout: u64,
    resilient_open_scavenger_expiry_time: u64,
    client_table: HashMap<Uuid, SMBClient>,
    encrypt_data: bool,
    unencrypted_access: bool,
    multi_channel_capable: bool,
    anonymous_access: bool,
    shared_vhd_supported: bool,
    max_cluster_dialect: SMBDialect,
    tree_connect_extension: bool,
    named_pipe_access_over_quic: bool,
}

pub struct SMBServerBuilder {
    share_list: HashMap<String, Box<dyn SharedResource>>,
    guid: Uuid,
    copy_max_chunks: u64,
    copy_max_chunk_size: u64,
    copy_max_data_size: u64,
    hash_level: HashLevel,
    max_resiliency_timeout: u64,
    encrypt_data: bool,
    unencrypted_access: bool,
    multi_channel_capable: bool,
    anonymous_access: bool,
    max_cluster_dialect: SMBDialect,
    tree_connect_extension: bool,
    named_pipe_access_over_quic: bool,
}

impl Default for SMBServerBuilder {
    fn default() -> Self {
        Self {
            share_list: Default::default(),
            guid: Uuid::new_v4(),
            copy_max_chunks: 100,
            copy_max_chunk_size: 1024,
            copy_max_data_size: 1024,
            hash_level: HashLevel::EnableAll,
            max_resiliency_timeout: 5000,
            encrypt_data: true,
            unencrypted_access: false,
            multi_channel_capable: true,
            max_cluster_dialect: SMBDialect::V3_1_1,
            tree_connect_extension: true,
            named_pipe_access_over_quic: false,
            anonymous_access: false,
        }
    }
}

impl SMBServerBuilder {
    fn add_share(&mut self, name: String, share: Box<dyn SharedResource>) -> &mut Self {
        self.share_list.insert(name, share);
        self
    }

    fn set_guid(&mut self, guid: Uuid) -> &mut Self {
        self.guid = guid;
        self
    }

    fn set_copy_max_chunks(&mut self, copy_max_chunks: u64) -> &mut Self {
        self.copy_max_chunks = copy_max_chunks;
        self
    }

    fn set_copy_max_chunk_size(&mut self, copy_max_chunk_size: u64) -> &mut Self {
        self.copy_max_chunk_size = copy_max_chunk_size;
        self
    }

    fn set_copy_max_data_size(&mut self, copy_max_data_size: u64) -> &mut Self {
        self.copy_max_data_size = copy_max_data_size;
        self
    }

    fn set_hash_level(&mut self, hash_level: HashLevel) -> &mut Self {
        self.hash_level = hash_level;
        self
    }

    fn set_max_resiliency_timeout(&mut self, max_resiliency_timeout: u64) -> &mut Self {
        self.max_resiliency_timeout = max_resiliency_timeout;
        self
    }

    fn encrypts_data(&mut self, encrypt_data: bool) -> &mut Self {
        self.encrypt_data = encrypt_data;
        self
    }

    fn allows_unencrypted_access(&mut self, unencrypted_access: bool) -> &mut Self {
        self.unencrypted_access = unencrypted_access;
        self
    }

    fn is_multi_channel_capable(&mut self, multi_channel_capable: bool) -> &mut Self {
        self.multi_channel_capable = multi_channel_capable;
        self
    }

    fn set_max_cluster_dialect(&mut self, max_cluster_dialect: SMBDialect) -> &mut Self {
        self.max_cluster_dialect = max_cluster_dialect;
        self
    }

    fn supports_tree_connect_extension(&mut self, tree_connect_extension: bool) -> &mut Self {
        self.tree_connect_extension = tree_connect_extension;
        self
    }

    fn allows_anonymous_access(&mut self, anonymous_access: bool) -> &mut Self {
        self.anonymous_access = anonymous_access;
        self
    }

    fn allows_named_pipe_access_over_quic(&mut self, named_pipe_access_over_quic: bool) -> &mut Self {
        self.named_pipe_access_over_quic = named_pipe_access_over_quic;
        self
    }

    fn build(self) -> SMBServer {
        SMBServer {
            statistics: Default::default(),
            enabled: false,
            share_list: self.share_list,
            open_table: Default::default(),
            session_table: Default::default(),
            connection_list: Default::default(),
            guid: self.guid,
            start_time: Default::default(),
            dfs_capable: false,
            copy_max_chunks: self.copy_max_chunks,
            copy_max_chunk_size: self.copy_max_chunk_size,
            copy_max_data_size: self.copy_max_data_size,
            hash_level: self.hash_level,
            lease_table_list: Default::default(),
            max_resiliency_timeout: self.max_resiliency_timeout,
            resilient_open_scavenger_expiry_time: 0,
            client_table: Default::default(),
            encrypt_data: self.encrypt_data,
            unencrypted_access: self.unencrypted_access,
            multi_channel_capable: self.multi_channel_capable,
            anonymous_access: self.anonymous_access,
            shared_vhd_supported: false,
            max_cluster_dialect: self.max_cluster_dialect,
            tree_connect_extension: self.tree_connect_extension,
            named_pipe_access_over_quic: self.named_pipe_access_over_quic,
        }
    }
}

#[derive(Debug, Default)]
pub enum HashLevel {
    #[default]
    EnableAll,
    DisableAll,
    EnableShare
}

impl SMBServer {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn initialize(&mut self) {
        self.statistics = ServerDiagnostics::new();
        self.guid = Uuid::new_v4();
        *self = Self::new()
    }

    pub fn add_share(&mut self, name: String, share: Box<dyn SharedResource>) {
        self.share_list.insert(name, share);
    }

    pub fn remove_share(&mut self, name: &str) {
        self.share_list.remove(name);
    }
}

#[derive(Debug, Default)]
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

impl ServerDiagnostics {
    pub fn new() -> Self {
        Default::default()
    }
}