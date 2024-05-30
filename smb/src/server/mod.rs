use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::sync::{Arc, Weak};

use derive_builder::Builder;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_stream::StreamExt;
use uuid::Uuid;

use smb_core::error::SMBError;
use smb_core::SMBResult;

use crate::protocol::body::dialect::SMBDialect;
use crate::protocol::body::filetime::FileTime;
use crate::server::client::SMBClient;
use crate::server::connection::{Connection, SMBConnection};
use crate::server::lease::{Lease, SMBLease, SMBLeaseTable};
use crate::server::open::{Open, SMBOpen};
use crate::server::safe_locked_getter::InnerGetter;
use crate::server::session::{Session, SMBSession};
use crate::server::share::{ConnectAllowed, FilePerms, ResourceHandle, SharedResource};
use crate::server::share::file_system::{SMBFileSystemHandle, SMBFileSystemShare};
use crate::socket::listener::{SMBListener, SMBSocket};
use crate::util::auth::{AuthContext, AuthProvider};
use crate::util::auth::ntlm::NTLMAuthProvider;

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
mod message_handler;
mod safe_locked_getter;

pub trait Server: Send + Sync {
    type Connection: Connection<Server=Self> + InnerGetter<Upper=Self>;
    type Session: Session<Self::Connection, Self::AuthProvider, Self::Open> + InnerGetter<Upper=Self::Connection>;
    type Share: SharedResource<UserName=<<Self::AuthProvider as AuthProvider>::Context as AuthContext>::UserName, Handle=Self::Handle>;
    type Open: Open<Server=Self>;
    type Lease: Lease;
    type AuthProvider: AuthProvider;
    type Handle: ResourceHandle;
    fn shares(&self) -> &HashMap<String, Arc<Self::Share>>;
    fn opens(&self) -> &HashMap<u32, Arc<RwLock<Self::Open>>>;
    fn add_open(&mut self, open: Arc<RwLock<Self::Open>>) -> impl Future<Output=u32>;
    fn sessions(&self) -> &HashMap<u64, Arc<RwLock<Self::Session>>>;
    fn sessions_mut(&mut self) -> &mut HashMap<u64, Arc<RwLock<Self::Session>>>;
    fn guid(&self) -> Uuid;
    fn dfs_capable(&self) -> bool;
    fn copy_max_chunks(&self) -> u64;
    fn copy_max_chunk_size(&self) -> u64;
    fn copy_max_data_size(&self) -> u64;
    fn hash_level(&self) -> &HashLevel;
    fn lease_table_list(&self) -> &HashMap<Uuid, SMBLeaseTable<Self::Lease>>;
    fn max_resiliency_timeout(&self) -> u64;
    fn client_table(&self) -> &HashMap<Uuid, SMBClient>;
    fn encrypt_data(&self) -> bool;
    fn unencrypted_access(&self) -> bool;
    fn multi_channel_capable(&self) -> bool;
    fn anonymous_access(&self) -> bool;
    fn require_message_signing(&self) -> bool;
    fn encryption_supported(&self) -> bool;
    fn compression_supported(&self) -> bool;
    fn chained_compression_supported(&self) -> bool;
    fn rdma_transform_supported(&self) -> bool;
    fn disable_encryption_over_secure_transport(&self) -> bool;
    fn auth_provider(&self) -> &Arc<Self::AuthProvider>;
}

pub trait StartSMBServer {
    fn start(&self) -> impl Future<Output=SMBResult<()>> + Send;
}

type SMBConnectionType<Addr, L, A, S, H> = SMBConnection<<L as SMBSocket<Addr>>::ReadStream, <L as SMBSocket<Addr>>::WriteStream, SMBServer<Addr, L, A, S, H>>;

type LockedWeakSMBConnection<Addr, L, A, S, H> = Weak<RwLock<SMBConnectionType<Addr, L, A, S, H>>>;
type SMBSessionType<Addr, L, A, S, H> = SMBSession<SMBServer<Addr, L, A, S, H>>;
type SMBOpenType<Addr, L, A, S, H> = SMBOpen<SMBServer<Addr, L, A, S, H>>;
type SMBLeaseType<Addr, L, A, S, H> = SMBLease<SMBServer<Addr, L, A, S, H>>;
type UserName<Auth> = <<Auth as AuthProvider>::Context as AuthContext>::UserName;
pub type DefaultShare<Auth> = Box<dyn SharedResource<UserName=<<Auth as AuthProvider>::Context as AuthContext>::UserName, Handle=DefaultHandle>>;
type DefaultHandle = Box<dyn ResourceHandle>;
#[derive(Debug, Builder)]
#[builder(pattern = "owned")]
#[builder(build_fn(name = "build_inner", private))]
pub struct SMBServer<Addrs: Send + Sync, Listener: SMBSocket<Addrs> = TcpListener, Auth: AuthProvider = NTLMAuthProvider, Share: SharedResource<UserName=UserName<Auth>, Handle=Handle> = DefaultShare<Auth>, Handle: ResourceHandle = DefaultHandle> {
    #[builder(default = "Default::default()")]
    statistics: Arc<RwLock<SMBServerDiagnostics>>,
    #[builder(default = "false")]
    enabled: bool,
    #[builder(field(type = "HashMap<String, Arc<Share>>"))]
    share_list: HashMap<String, Arc<Share>>,
    #[builder(field(
        type = "HashMap<u32, Arc<RwLock<SMBOpenType<Addrs, Listener, Auth, Share, Handle>>>>"
    ))]
    open_table: HashMap<u32, Arc<RwLock<SMBOpenType<Addrs, Listener, Auth, Share, Handle>>>>,
    #[builder(field(
        type = "HashMap<u64, Arc<RwLock<SMBSessionType<Addrs, Listener, Auth, Share, Handle>>>>"
    ))]
    session_table: HashMap<u64, Arc<RwLock<SMBSessionType<Addrs, Listener, Auth, Share, Handle>>>>,
    #[builder(field(
        type = "HashMap<String, LockedWeakSMBConnection<Addrs, Listener, Auth, Share, Handle>>"
    ))]
    connection_list: HashMap<String, LockedWeakSMBConnection<Addrs, Listener, Auth, Share, Handle>>,
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
    #[builder(field(
        type = "HashMap<Uuid, SMBLeaseTable<SMBLeaseType<Addrs, Listener, Auth, Share, Handle>>>"
    ))]
    lease_table_list: HashMap<Uuid, SMBLeaseTable<SMBLeaseType<Addrs, Listener, Auth, Share, Handle>>>,
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
    #[builder(default = "true")]
    require_message_signing: bool,
    #[builder(default = "false")]
    encryption_supported: bool,
    #[builder(default = "false")]
    compression_supported: bool,
    #[builder(default = "false")]
    rdma_transform_supported: bool,
    #[builder(default = "false")]
    chained_compression_supported: bool,
    #[builder(default = "true")]
    disable_encryption_over_secure_transport: bool,
    local_listener: Arc<Mutex<SMBListener<Addrs, Listener>>>,
    #[builder(setter(custom))]
    auth_provider: Arc<Auth>,
}

impl<Addrs: Send + Sync, Listener: SMBSocket<Addrs>, Auth: AuthProvider, Share: SharedResource<UserName=UserName<Auth>, Handle=Handle>, Handle: ResourceHandle> Server for SMBServer<Addrs, Listener, Auth, Share, Handle> {
    type Connection = SMBConnectionType<Addrs, Listener, Auth, Share, Handle>;
    type Session = SMBSessionType<Addrs, Listener, Auth, Share, Handle>;
    type Share = Share;
    type Open = SMBOpenType<Addrs, Listener, Auth, Share, Handle>;
    type Lease = SMBLeaseType<Addrs, Listener, Auth, Share, Handle>;
    type AuthProvider = Auth;
    type Handle = Handle; 

    fn shares(&self) -> &HashMap<String, Arc<Self::Share>> {
        &self.share_list
    }

    fn opens(&self) -> &HashMap<u32, Arc<RwLock<Self::Open>>> {
        &self.open_table
    }

    async fn add_open(&mut self, open: Arc<RwLock<Self::Open>>) -> u32 {
        for i in 0..u32::MAX {
            if self.open_table.get(&i).is_none() {
                let mut open_wr = open.write().await;
                open_wr.set_global_id(i);
                drop(open_wr);
                self.open_table.insert(i, open);
                return i;
            }
        }
        0
    }

    fn sessions(&self) -> &HashMap<u64, Arc<RwLock<Self::Session>>> {
        &self.session_table
    }

    fn sessions_mut(&mut self) -> &mut HashMap<u64, Arc<RwLock<Self::Session>>> {
        &mut self.session_table
    }

    fn guid(&self) -> Uuid {
        self.guid
    }

    fn dfs_capable(&self) -> bool {
        self.dfs_capable
    }

    fn copy_max_chunks(&self) -> u64 {
        self.copy_max_chunks
    }

    fn copy_max_chunk_size(&self) -> u64 {
        self.copy_max_chunk_size
    }

    fn copy_max_data_size(&self) -> u64 {
        self.copy_max_data_size
    }

    fn hash_level(&self) -> &HashLevel {
        &self.hash_level
    }

    fn lease_table_list(&self) -> &HashMap<Uuid, SMBLeaseTable<Self::Lease>> {
        &self.lease_table_list
    }

    fn max_resiliency_timeout(&self) -> u64 {
        self.max_resiliency_timeout
    }

    fn client_table(&self) -> &HashMap<Uuid, SMBClient> {
        &self.client_table
    }

    fn encrypt_data(&self) -> bool {
        self.encrypt_data
    }

    fn unencrypted_access(&self) -> bool {
        self.unencrypted_access
    }

    fn multi_channel_capable(&self) -> bool {
        self.multi_channel_capable
    }

    fn anonymous_access(&self) -> bool {
        self.anonymous_access
    }

    fn require_message_signing(&self) -> bool {
        self.require_message_signing
    }

    fn encryption_supported(&self) -> bool {
        self.encryption_supported
    }

    fn compression_supported(&self) -> bool {
        self.compression_supported
    }

    fn chained_compression_supported(&self) -> bool {
        self.chained_compression_supported
    }

    fn rdma_transform_supported(&self) -> bool {
        self.rdma_transform_supported
    }

    fn disable_encryption_over_secure_transport(&self) -> bool {
        self.disable_encryption_over_secure_transport
    }

    fn auth_provider(&self) -> &Arc<Self::AuthProvider> {
        &self.auth_provider
    }
}

impl<Addrs: Send + Sync, Listener: SMBSocket<Addrs>, Auth: AuthProvider, Share: SharedResource<UserName=UserName<Auth>, Handle=Handle>, Handle: ResourceHandle> SMBServerBuilder<Addrs, Listener, Auth, Share, Handle> {
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

    pub fn add_share<Key: Into<String>>(mut self, key: Key, share: Share) -> Self {
        self.share_list.insert(key.into(), Arc::new(share));
        self
    }

    pub fn build(self) -> SMBResult<Arc<RwLock<SMBServer<Addrs, Listener, Auth, Share, Handle>>>> {
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

impl<Addrs: Send + Sync, Listener: SMBSocket<Addrs>, Auth: AuthProvider + 'static, Share: SharedResource<UserName=UserName<Auth>, Handle=Handle>, Handle: ResourceHandle + 'static> SMBServer<Addrs, Listener, Auth, Share, Handle> {
    pub fn initialize(&mut self) {
        self.statistics = Default::default();
        self.guid = Uuid::new_v4();
        // *self = Self::new()
    }

    pub fn add_share(&mut self, name: String, share: Arc<Share>) {
        self.share_list.insert(name, share);
    }

    pub fn remove_share(&mut self, name: &str) {
        self.share_list.remove(name);
    }
}

impl<
    Addrs: Send + Sync,
    Listener: SMBSocket<Addrs>,
    Auth: AuthProvider + 'static,
    Share: SharedResource<UserName=UserName<Auth>, Handle=Handle> + From<SMBFileSystemShare<UserName<Auth>, Handle>>,
    Handle: ResourceHandle + 'static + From<SMBFileSystemHandle> + TryInto<SMBFileSystemHandle>
> SMBServerBuilder<Addrs, Listener, Auth, Share, Handle> {
    pub fn add_fs_share(mut self, name: String, path: String, connect_allowed: ConnectAllowed<UserName<Auth>>, file_perms: FilePerms<UserName<Auth>>) -> Self {
        let share = SMBFileSystemShare::path(name.clone(), path, connect_allowed, file_perms);
        self.add_share(name, share.into())
    }
}

impl<Addrs: Send + Sync + 'static, Listener: SMBSocket<Addrs> + 'static, Auth: AuthProvider + 'static, Share: SharedResource<UserName=UserName<Auth>, Handle=Handle> + 'static, Handle: ResourceHandle + 'static> StartSMBServer for Arc<RwLock<SMBServer<Addrs, Listener, Auth, Share, Handle>>> {
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
            tokio::spawn(async move {
                let mut stream = socket.lock().await;
                let _ = SMBConnection::start_message_handler::<Auth>(&mut stream, wrapped_connection, update_channel).await;
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