use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Weak};

use derive_builder::Builder;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_stream::StreamExt;
use uuid::Uuid;

use smb_core::error::SMBError;
use smb_core::SMBResult;

use crate::protocol::body::{FileTime, SMBDialect};
use crate::server::client::SMBClient;
use crate::server::connection::SMBConnection;
use crate::server::lease::SMBLeaseTable;
use crate::server::open::Open;
use crate::server::session::Session;
use crate::server::share::SharedResource;
use crate::socket::listener::{SMBListener, SMBSocket};
use crate::util::auth::AuthProvider;

pub mod client;
pub mod channel;
pub mod connection;
pub mod lease;
pub mod open;
pub mod preauth_session;
pub mod request;
pub mod session;
pub mod share;
pub mod tree_connect;

pub trait Server: Send + Sync {}

pub trait StartSMBServer {
    fn start(&self) -> impl Future<Output=SMBResult<()>> + Send;
}

type LockedWeakSMBConnection<Addr, L, A> = Weak<RwLock<SMBConnection<<L as SMBSocket<Addr>>::ReadStream, <L as SMBSocket<Addr>>::WriteStream, SMBServer<Addr, L, A>>>>;

#[derive(Debug, Builder)]
#[builder(pattern = "owned")]
#[builder(build_fn(name = "build_inner", private))]
pub struct SMBServer<Addrs: Send + Sync, Listener: SMBSocket<Addrs>, Auth: AuthProvider> {
    #[builder(default = "Default::default()")]
    statistics: Arc<RwLock<SMBServerDiagnostics>>,
    #[builder(default = "false")]
    enabled: bool,
    #[builder(field(type = "HashMap<String, Box<dyn SharedResource>>"))]
    share_list: HashMap<String, Box<dyn SharedResource>>,
    #[builder(field(type = "HashMap<u64, Box<dyn Open>>"))]
    open_table: HashMap<u64, Box<dyn Open>>,
    #[builder(field(type = "HashMap<u64, Box<dyn Session>>"))]
    session_table: HashMap<u64, Box<dyn Session>>,
    #[builder(field(type = "HashMap<String, LockedWeakSMBConnection<Addrs, Listener, Auth>>"))]
    connection_list: HashMap<String, LockedWeakSMBConnection<Addrs, Listener, Auth>>,
    #[builder(default = "Uuid::new_v4()")]
    guid: Uuid,
    #[builder(default = "FileTime::default()")]
    start_time: FileTime,
    #[builder(default = "false")]
    dfs_capable: bool,
    #[builder(default = "10")]
    copy_max_chunks: u64,
    #[builder(default = "1024")]
    copy_max_chunk_size: u64,
    #[builder(default = "1024")]
    copy_max_data_size: u64,
    #[builder(default = "HashLevel::EnableAll")]
    hash_level: HashLevel,
    #[builder(field(type = "HashMap<Uuid, SMBLeaseTable>"))]
    lease_table_list: HashMap<Uuid, SMBLeaseTable>,
    #[builder(default = "5000")]
    max_resiliency_timeout: u64,
    #[builder(default = "5000")]
    resilient_open_scavenger_expiry_time: u64,
    #[builder(field(type = "HashMap<Uuid, SMBClient>"))]
    client_table: HashMap<Uuid, SMBClient>,
    #[builder(default = "true")]
    encrypt_data: bool,
    #[builder(default = "false")]
    unencrypted_access: bool,
    #[builder(default = "true")]
    multi_channel_capable: bool,
    #[builder(default = "false")]
    anonymous_access: bool,
    #[builder(default = "true")] // TODO
    shared_vhd_supported: bool,
    #[builder(default = "SMBDialect::V3_1_1")]
    max_cluster_dialect: SMBDialect,
    #[builder(default = "true")]
    tree_connect_extension: bool,
    #[builder(default = "true")]
    named_pipe_access_over_quic: bool,
    local_listener: Arc<Mutex<SMBListener<Addrs, Listener>>>,
    #[builder(setter(custom))]
    auth_provider: Arc<Auth>,
}

impl<Addrs: Send + Sync, Listener: SMBSocket<Addrs>, Auth: AuthProvider> Server for SMBServer<Addrs, Listener, Auth> {}

impl<Addrs: Send + Sync, Listener: SMBSocket<Addrs>, Auth: AuthProvider> SMBServerBuilder<Addrs, Listener, Auth> {
    #[cfg(not(feature = "async"))]
    pub fn listener_address(self, addr: Addrs) -> SMBResult<Self> {
        Ok(self.local_listener(SMBListener::new(addr)?))
    }

    #[cfg(feature = "async")]
    pub async fn listener_address(self, addr: Addrs) -> SMBResult<Self> {
        Ok(self.local_listener(Arc::new(Mutex::new(SMBListener::new(addr).await?))))
    }

    pub fn auth_provider(mut self, provider: Auth) -> Self {
        self.auth_provider = Some(Arc::new(provider));
        self
    }

    pub fn add_share<Key: Into<String>, S: SharedResource + 'static>(mut self, key: Key, share: S) -> Self {
        self.share_list.insert(key.into(), Box::new(share));
        self
    }

    pub fn build(self) -> SMBResult<Arc<RwLock<SMBServer<Addrs, Listener, Auth>>>> {
        let server = self.build_inner().map_err(SMBError::server_error)?;
        Ok(Arc::new(RwLock::new(server)))
    }
}

#[derive(Debug, Default)]
pub enum HashLevel {
    #[default]
    EnableAll,
    DisableAll,
    EnableShare,
}

impl<Addrs: Send + Sync, Listener: SMBSocket<Addrs>, Auth: AuthProvider + 'static> SMBServer<Addrs, Listener, Auth> {
    pub fn initialize(&mut self) {
        self.statistics = Default::default();
        self.guid = Uuid::new_v4();
        // *self = Self::new()
    }

    pub fn add_share(&mut self, name: String, share: Box<dyn SharedResource>) {
        self.share_list.insert(name, share);
    }

    pub fn remove_share(&mut self, name: &str) {
        self.share_list.remove(name);
    }
}

impl<Addrs: Send + Sync + 'static, Listener: SMBSocket<Addrs> + 'static, Auth: AuthProvider + 'static> StartSMBServer for Arc<RwLock<SMBServer<Addrs, Listener, Auth>>> {
    async fn start(&self) -> SMBResult<()> {
        let (rx, mut tx) = mpsc::channel(10);
        let diagnostics = {
            self.read().await.statistics.clone()
        };
        tokio::spawn(async move {
            while let Some(update) = tx.recv().await {
                diagnostics.write().await.update(update);
            }
        });
        let listener = {
            self.read().await.local_listener.clone()
        };
        while let Some(connection) = listener.lock().await.connections().next().await {
            println!("got connection");
            let smb_connection = SMBConnection::try_from((connection, Arc::downgrade(self)))?;
            let name = smb_connection.client_name().to_string();
            let socket = smb_connection.underlying_socket();
            let wrapped_connection = Arc::new(RwLock::new(smb_connection));
            {
                self.write().await.connection_list.insert(name, Arc::downgrade(&wrapped_connection));
            }
            let update_channel = rx.clone();
            let auth_provider = {
                self.read().await.auth_provider.clone()
            };
            tokio::spawn(async move {
                let mut stream = socket.lock().await;
                let _ = SMBConnection::start_message_handler(&mut stream, wrapped_connection, auth_provider, update_channel).await;
            });
        }

        Ok(())
    }
}

#[derive(Debug, Default, Builder)]
#[builder(name = "SMBServerDiagnosticsUpdate", pattern = "owned", derive(Debug))]
pub struct SMBServerDiagnostics {
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
    big_buffer_need: u32,
}

impl SMBServerDiagnostics {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn on_received(&mut self, size: u64) {
        self.bytes_received += size;
    }

    pub fn on_sent(&mut self, size: u64) {
        self.bytes_sent += size;
    }

    pub fn update(&mut self, update: SMBServerDiagnosticsUpdate) {
        if let Some(start) = update.start {
            self.start = start;
        }
        if let Some(file_opens) = update.file_opens {
            self.file_opens += file_opens;
        }
        if let Some(device_opens) = update.device_opens {
            self.device_opens = device_opens;
        }
        if let Some(jobs_queued) = update.jobs_queued {
            self.jobs_queued += jobs_queued;
        }
        if let Some(session_opens) = update.session_opens {
            self.session_opens = session_opens;
        }
        if let Some(session_timed_out) = update.session_timed_out {
            self.session_timed_out += session_timed_out;
        }
        if let Some(session_error_out) = update.session_error_out {
            self.session_error_out += session_error_out;
        }
        if let Some(password_errors) = update.password_errors {
            self.password_errors += password_errors;
        }
        if let Some(permission_errors) = update.permission_errors {
            self.permission_errors += permission_errors;
        }
        if let Some(system_errors) = update.system_errors {
            self.system_errors += system_errors;
        }
        if let Some(bytes_sent) = update.bytes_sent {
            self.bytes_sent += bytes_sent;
        }
        if let Some(bytes_received) = update.bytes_received {
            self.bytes_received += bytes_received;
        }
        if let Some(average_response) = update.average_response {
            self.average_response = average_response;
        }
        if let Some(request_buffer_need) = update.request_buffer_need {
            self.request_buffer_need += request_buffer_need;
        }
        if let Some(big_buffer_need) = update.big_buffer_need {
            self.big_buffer_need += big_buffer_need;
        }
    }
}