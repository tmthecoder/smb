use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Weak};

use derive_builder::Builder;
use digest::Digest;
use sha2::Sha512;
use tokio::sync::{Mutex, RwLock};
use tokio::sync::mpsc::Sender;
use tokio_stream::StreamExt;
use uuid::Uuid;

use smb_core::{SMBResult, SMBToBytes};
use smb_core::error::SMBError;
use smb_core::nt_status::NTStatus;

use crate::protocol::body::capabilities::Capabilities;
use crate::protocol::body::create::SMBCreateRequest;
use crate::protocol::body::dialect::SMBDialect;
use crate::protocol::body::filetime::FileTime;
use crate::protocol::body::negotiate::{SMBNegotiateRequest, SMBNegotiateResponse};
use crate::protocol::body::negotiate::context::{CompressionAlgorithm, EncryptionCipher, HashAlgorithm, RDMATransformID, SigningAlgorithm};
use crate::protocol::body::negotiate::security_mode::NegotiateSecurityMode;
use crate::protocol::body::session_setup::flags::SMBSessionSetupFlags;
use crate::protocol::body::session_setup::SMBSessionSetupRequest;
use crate::protocol::body::SMBBody;
use crate::protocol::header::SMBSyncHeader;
use crate::protocol::message::SMBMessage;
use crate::server::{Server, SMBServerDiagnosticsUpdate};
use crate::server::message_handler::{NonEndingHandler, SMBHandlerState, SMBLockedMessageHandler, SMBLockedMessageHandlerBase, SMBMessageType};
use crate::server::open::Open;
use crate::server::preauth_session::SMBPreauthSession;
use crate::server::request::Request;
use crate::server::safe_locked_getter::{InnerGetter, SafeLockedGetter};
use crate::server::session::Session;
use crate::socket::message_stream::{SMBReadStream, SMBSocketConnection, SMBWriteStream};
use crate::util::auth::{AuthMessage, AuthProvider};

// use tokio::sync::Mutex;
// use tokio_stream::StreamExt;

pub trait Connection: Send + Sync {
    type Server: Server;
    fn client_capabilities(&self) -> Capabilities;

    fn negotiate_dialect(&self) -> SMBDialect;
    fn dialect(&self) -> SMBDialect;

    fn should_sign(&self) -> bool;
    fn client_name(&self) -> &str;
    fn max_transact_size(&self) -> u32;
    fn max_write_size(&self) -> u32;
    fn max_read_size(&self) -> u32;

    fn supports_multi_credit(&self) -> bool;
    fn transport_name(&self) -> &str;

    fn client_guid(&self) -> Uuid;

    fn server_capabilities(&self) -> Capabilities;

    fn client_security_mode(&self) -> NegotiateSecurityMode;
    fn server_security_mode(&self) -> NegotiateSecurityMode;
    fn posix_extension_payload(&self) -> &[u8];

    fn preauth_integrity_hash_id(&self) -> HashAlgorithm;

    fn preauth_integtiry_hash_value(&self) -> &Vec<u8>;

    fn cipher_id(&self) -> EncryptionCipher;
    fn compression_ids(&self) -> &Vec<CompressionAlgorithm>;
    fn supports_chained_compression(&self) -> bool;

    fn rdma_transform_ids(&self) -> &Vec<RDMATransformID>;
    fn signing_algorithm_id(&self) -> SigningAlgorithm;
    fn accept_transport_security(&self) -> bool;
    fn preauth_sessions(&self) -> &HashMap<u64, SMBPreauthSession>;

    fn server_ref(&self) -> Weak<RwLock<Self::Server>>;
}

#[derive(Builder)]
#[builder(name = "SMBConnectionUpdate", pattern = "owned")]
#[builder(build_fn(skip))]
pub struct SMBConnection<R: SMBReadStream, W: SMBWriteStream, S: Server> {
    command_sequence_window: Vec<u32>,
    request_list: HashMap<u64, Box<dyn Request>>,
    client_capabilities: Capabilities,
    negotiate_dialect: SMBDialect,
    async_command_list: HashMap<u64, Box<dyn Request>>,
    dialect: SMBDialect,
    should_sign: bool,
    client_name: String,
    max_transact_size: u32,
    max_write_size: u32,
    max_read_size: u32,
    supports_multi_credit: bool,
    transport_name: String,
    session_table: HashMap<u64, Arc<RwLock<S::Session>>>,
    creation_time: FileTime,
    preauth_session_table: HashMap<u64, SMBPreauthSession>, // TODO
    client_guid: Uuid,
    server_capabilites: Capabilities,
    client_security_mode: NegotiateSecurityMode,
    server_security_mode: NegotiateSecurityMode,
    constrained_connection: bool,
    preauth_integrity_hash_id: HashAlgorithm,
    posix_extension_payload: Vec<u8>,
    // TODO
    preauth_integrity_hash_value: Vec<u8>, // TODO
    cipher_id: EncryptionCipher,
    client_dialects: Vec<SMBDialect>,
    compression_ids: Vec<CompressionAlgorithm>, // TODO ??
    supports_chained_compression: bool,
    rdma_transform_ids: Vec<RDMATransformID>, // TODO ??
    signing_algorithm_id: SigningAlgorithm,
    accept_transport_security: bool,
    underlying_stream: Arc<Mutex<SMBSocketConnection<R, W>>>,
    server: Weak<RwLock<S>>
}

// Getters
impl<R: SMBReadStream, W: SMBWriteStream, S: Server> Connection for SMBConnection<R, W, S> {
    type Server = S;

    fn client_capabilities(&self) -> Capabilities {
        self.client_capabilities
    }

    fn negotiate_dialect(&self) -> SMBDialect {
        self.negotiate_dialect
    }
    fn dialect(&self) -> SMBDialect {
        self.dialect
    }

    fn should_sign(&self) -> bool {
        self.should_sign
    }

    fn client_name(&self) -> &str {
        &self.client_name
    }
    fn max_transact_size(&self) -> u32 {
        self.max_transact_size
    }
    fn max_write_size(&self) -> u32 {
        self.max_write_size
    }

    fn max_read_size(&self) -> u32 {
        self.max_read_size
    }

    fn supports_multi_credit(&self) -> bool {
        self.supports_multi_credit
    }
    fn transport_name(&self) -> &str {
        &self.transport_name
    }

    fn client_guid(&self) -> Uuid {
        self.client_guid
    }

    fn server_capabilities(&self) -> Capabilities {
        self.server_capabilites
    }

    fn client_security_mode(&self) -> NegotiateSecurityMode {
        self.client_security_mode
    }
    fn server_security_mode(&self) -> NegotiateSecurityMode {
        self.server_security_mode
    }

    fn posix_extension_payload(&self) -> &[u8] {
        &self.posix_extension_payload
    }

    fn preauth_integrity_hash_id(&self) -> HashAlgorithm {
        self.preauth_integrity_hash_id
    }

    fn preauth_integtiry_hash_value(&self) -> &Vec<u8> {
        &self.preauth_integrity_hash_value
    }

    fn cipher_id(&self) -> EncryptionCipher {
        self.cipher_id
    }
    fn compression_ids(&self) -> &Vec<CompressionAlgorithm> {
        &self.compression_ids
    }
    fn supports_chained_compression(&self) -> bool {
        self.supports_chained_compression
    }

    fn rdma_transform_ids(&self) -> &Vec<RDMATransformID> {
        &self.rdma_transform_ids
    }
    fn signing_algorithm_id(&self) -> SigningAlgorithm {
        self.signing_algorithm_id
    }

    fn accept_transport_security(&self) -> bool {
        self.accept_transport_security
    }

    fn preauth_sessions(&self) -> &HashMap<u64, SMBPreauthSession> {
        &self.preauth_session_table
    }

    fn server_ref(&self) -> Weak<RwLock<Self::Server>> {
        self.server.clone()
    }
}

impl<R: SMBReadStream, W: SMBWriteStream, S: Server<Connection=Self>> SMBConnection<R, W, S>
    where Arc<RwLock<S::Session>>: SMBLockedMessageHandler {
    pub async fn start_message_handler<A: AuthProvider>(stream: &mut SMBSocketConnection<R, W>, mut connection: Arc<RwLock<SMBConnection<R, W, S>>>, update_channel: Sender<SMBServerDiagnosticsUpdate>) -> SMBResult<()> {
        let (read, write) = stream.streams();
        println!("Start message handler");
        let mut messages = read.messages();
        while let Some(message) = messages.next().await {
            println!("Got message: {:?}", message);
            let message = connection.handle_message(&message).await;
            // let message = match message.header.command_code() {
            //     SMBCommandCode::LegacyNegotiate => connection.handle_legacy_negotiate(),
            //     SMBCommandCode::Negotiate => connection.handle_negotiate(&message).await,
            //     SMBCommandCode::SessionSetup => connection.handle_session_setup(&server, message).await,
            //     SMBCommandCode::LogOff => {
            //         println!("got logoff");
            //         break;
            //     }
            //     _ => connection.generic_message_handler(message).await
            // };
            println!("After handler: {:?}", message);
            if let Ok(message) = message {
                println!("Writing message {:?}", message);
                let sent = write.write_message(&message).await?;
                let _ = update_channel.send(SMBServerDiagnosticsUpdate::default().bytes_sent(sent as u64)).await;
            }
            // TODO handle error response (SMBError::ResponseError)
        }

        // Close streams on message parse finish (logoff)
        let _ = write.close_stream().await;
        Ok(())
    }
}

impl<R: SMBReadStream, W: SMBWriteStream, S: Server<Connection=Self>> SMBConnection<R, W, S> {
    pub fn underlying_socket(&self) -> Arc<Mutex<SMBSocketConnection<R, W>>> {
        self.underlying_stream.clone()
    }
    pub fn sessions(&self) -> &HashMap<u64, Arc<RwLock<S::Session>>> {
        &self.session_table
    }
    pub fn apply_update(&mut self, mut update: SMBConnectionUpdate<R, W, S>) {
        if let Some(command_sequence_window) = update.command_sequence_window.take() {
            self.command_sequence_window.extend(command_sequence_window);
        }
        if let Some(request_list) = update.request_list.take() {
            self.request_list.extend(request_list);
        }
        if let Some(client_capabilities) = update.client_capabilities.take() {
            self.client_capabilities = client_capabilities;
        }
        if let Some(negotiate_dialect) = update.negotiate_dialect.take() {
            self.negotiate_dialect = negotiate_dialect;
        }
        if let Some(async_command_list) = update.async_command_list.take() {
            self.async_command_list.extend(async_command_list);
        }
        if let Some(dialect) = update.dialect.take() {
            self.dialect = dialect;
        }
        if let Some(should_sign) = update.should_sign.take() {
            self.should_sign = should_sign;
        }
        if let Some(client_name) = update.client_name.take() {
            self.client_name = client_name;
        }
        if let Some(max_transact_size) = update.max_transact_size.take() {
            self.max_transact_size = max_transact_size;
        }
        if let Some(max_write_size) = update.max_write_size.take() {
            self.max_write_size = max_write_size;
        }
        if let Some(max_read_size) = update.max_read_size.take() {
            self.max_read_size = max_read_size;
        }
        if let Some(supports_multi_credit) = update.supports_multi_credit.take() {
            self.supports_multi_credit = supports_multi_credit;
        }
        if let Some(transport_name) = update.transport_name.take() {
            self.transport_name = transport_name;
        }
        if let Some(session_table) = update.session_table.take() {
            self.session_table.extend(session_table);
        }
        if let Some(creation_time) = update.creation_time.take() {
            self.creation_time = creation_time;
        }
        if let Some(session_table) = update.preauth_session_table.take() {
            self.preauth_session_table.extend(session_table);
        }
        if let Some(client_guid) = update.client_guid.take() {
            self.client_guid = client_guid;
        }
        if let Some(server_capabilities) = update.server_capabilites.take() {
            self.server_capabilites = server_capabilities;
        }
        if let Some(client_security_mode) = update.client_security_mode.take() {
            self.client_security_mode = client_security_mode;
        }
        if let Some(server_security_mode) = update.server_security_mode.take() {
            self.server_security_mode = server_security_mode;
        }
        if let Some(constrained_connection) = update.constrained_connection.take() {
            self.constrained_connection = constrained_connection;
        }
        if let Some(preauth_itegrity_hash_id) = update.preauth_integrity_hash_id.take() {
            self.preauth_integrity_hash_id = preauth_itegrity_hash_id;
        }
        if let Some(preauth_integrity_hash_value) = update.preauth_integrity_hash_value.take() {
            self.preauth_integrity_hash_value = preauth_integrity_hash_value;
        }
        if let Some(cipher_id) = update.cipher_id.take() {
            self.cipher_id = cipher_id;
        }
        if let Some(client_dialects) = update.client_dialects.take() {
            self.client_dialects = client_dialects;
        }
        if let Some(compression_ids) = update.compression_ids.take() {
            self.compression_ids = compression_ids;
        }
        if let Some(max_read_size) = update.supports_chained_compression.take() {
            self.supports_chained_compression = max_read_size;
        }
        if let Some(rdma_transform_ids) = update.rdma_transform_ids.take() {
            self.rdma_transform_ids = rdma_transform_ids;
        }
        if let Some(transport_name) = update.signing_algorithm_id.take() {
            self.signing_algorithm_id = transport_name;
        }
        if let Some(accept_transport_security) = update.accept_transport_security.take() {
            self.accept_transport_security = accept_transport_security;
        }
        if let Some(posix_extension_payload) = update.posix_extension_payload.take() {
            self.posix_extension_payload = posix_extension_payload;
        }
    }
}

type LockedSMBConnection<R, W, S> = Arc<RwLock<SMBConnection<R, W, S>>>;

impl<R: SMBReadStream, W: SMBWriteStream, S: Server<Connection=Self>> InnerGetter for SMBConnection<R, W, S> {
    type Upper = S;

    fn upper(&self) -> Option<Arc<RwLock<S>>> {
        self.server.upgrade()
    }
}


impl<R: SMBReadStream, W: SMBWriteStream, S: Server<Connection=Self>> SMBConnection<R, W, S> {
    fn handle_negotiate<A: AuthProvider>(&mut self, server: &S, header: &SMBSyncHeader, request: &SMBNegotiateRequest) -> SMBResult<SMBMessageType> {
        let (update, contexts) = request.validate_and_set_state(self, server)?;
        self.apply_update(update);
        let resp_header = header.create_response_header(0x0, 0, 0);
        let resp_body = SMBNegotiateResponse::from_connection_state::<A, R, W, S>(self, server, contexts);
        Ok(SMBMessage::new(resp_header, SMBBody::NegotiateResponse(resp_body)))
    }

    async fn handle_session_setup<F: FnOnce() -> Arc<RwLock<Self>>>(&mut self, server: &S, header: &SMBSyncHeader, request: &SMBSessionSetupRequest, get_locked: F) -> SMBResult<Arc<RwLock<S::Session>>> {
        let locked_conn = get_locked();
        let mut sha = Sha512::default();
        sha.update(self.preauth_integtiry_hash_value());
        sha.update(&request.smb_to_bytes());
        let preauth_val = sha.finalize().to_vec();
        let session = S::Session::init(1, server.encrypt_data(), preauth_val, Arc::downgrade(&locked_conn), server.auth_provider().clone());
        let id = session.id();
        let wrapped_session = Arc::new(RwLock::new(session));
        self.session_table.insert(id, wrapped_session.clone());
        let unlocked = wrapped_session.read().await;
        let update = request.validate_and_set_state(self, server, &unlocked, header).await?;
        drop(unlocked);
        self.apply_update(update);
        Ok(wrapped_session)
    }

    fn get_session(&self, server: &S, header: &SMBSyncHeader, flags: SMBSessionSetupFlags) -> SMBResult<Arc<RwLock<S::Session>>> {
        if self.dialect.is_smb3() && server.multi_channel_capable() && flags.contains(SMBSessionSetupFlags::BINDING) {
            server.sessions().get(&header.session_id)
        } else if !self.dialect.is_smb3() && !server.multi_channel_capable() && flags.contains(SMBSessionSetupFlags::BINDING) {
            None
        } else {
            self.sessions().get(&header.session_id)
        }.map(Arc::clone).ok_or(SMBError::response_error(NTStatus::UserSessionDeleted))
    }
}

impl<R: SMBReadStream, W: SMBWriteStream, S: Server<Connection=SMBConnection<R, W, S>>> NonEndingHandler for LockedSMBConnection<R, W, S> {}

impl<R: SMBReadStream, W: SMBWriteStream, S: Server<Connection=SMBConnection<R, W, S>>> SMBLockedMessageHandlerBase for LockedSMBConnection<R, W, S> {
    type Inner = Arc<RwLock<S::Session>>;

    async fn inner(&self, message: &SMBMessageType) -> Option<Arc<RwLock<S::Session>>> {
        println!("Getting inner for message {:?}", message);
        let read = self.read().await;
        let server = read.server.upgrade()?;
        let server_rd = server.read().await;
        println!("Getting session");
        // TODO
        if let SMBBody::SessionSetupRequest(req) = &message.body {
            read.get_session(&server_rd, &message.header, req.flags())
                .ok()
        } else {
            server_rd.sessions().get(&message.header.session_id)
                .or(read.sessions().get(&message.header.session_id))
                .map(Arc::clone)
        }
    }
    async fn handle_negotiate(&mut self, header: &SMBSyncHeader, message: &SMBNegotiateRequest) -> SMBResult<SMBHandlerState<Self::Inner>> {
        let server = self.upper().await?;
        let unlocked = server.read().await;
        let message = self.write().await.handle_negotiate::<S::AuthProvider>(&unlocked, header, message)?;
        Ok(SMBHandlerState::Finished(message))
    }

    async fn handle_session_setup(&mut self, header: &SMBSyncHeader, message: &SMBSessionSetupRequest) -> SMBResult<SMBHandlerState<Arc<RwLock<S::Session>>>> {
        let server = self.upper().await?;
        let unlocked = server.read().await;
        let cloned_arc = self.clone();
        let get_locked = || {
            cloned_arc
        };
        if header.session_id == 0 {
            let session = self.write().await.handle_session_setup(&unlocked, header, message, get_locked).await?;
            Ok(SMBHandlerState::Next(Some(session)))
        } else {
            Ok(SMBHandlerState::Next(None))
        }
    }

    async fn handle_create(&mut self, header: &SMBSyncHeader, message: &SMBCreateRequest) -> SMBResult<SMBHandlerState<Self::Inner>> {
        let server = self.upper().await?;
        let server_rd = server.read().await;
        let conn = self.read().await;
        // TODO check that RECONNECT or RECONNECT_V2 aren't included
        if conn.dialect == SMBDialect::V3_1_1 || conn.dialect == SMBDialect::V3_0_0 {
            for locked_open in server_rd.opens().values() {
                let open = locked_open.read().await;
                if open.file_name() == message.file_name() {
                    return Err(SMBError::response_error(NTStatus::FileNotAvailable));
                }
            }
        }
        Ok(SMBHandlerState::Next(None))
    }
}

impl<R: SMBReadStream, W: SMBWriteStream, S: Server> TryFrom<(SMBSocketConnection<R, W>, Weak<RwLock<S>>)> for SMBConnection<R, W, S> {
    type Error = SMBError;

    fn try_from(value: (SMBSocketConnection<R, W>, Weak<RwLock<S>>)) -> Result<Self, Self::Error> {
        let client_name = value.0.name().to_string();
        Ok(Self {
            command_sequence_window: vec![],
            request_list: Default::default(),
            client_capabilities: Capabilities::empty(),
            negotiate_dialect: Default::default(),
            async_command_list: Default::default(),
            dialect: Default::default(),
            should_sign: false,
            client_name,
            max_transact_size: 0,
            max_write_size: 0,
            max_read_size: 0,
            supports_multi_credit: false,
            transport_name: "".to_string(),
            session_table: Default::default(),
            creation_time: Default::default(),
            preauth_session_table: Default::default(),
            client_guid: Default::default(),
            server_capabilites: Capabilities::empty(),
            client_security_mode: NegotiateSecurityMode::empty(),
            server_security_mode: NegotiateSecurityMode::empty(),
            constrained_connection: false,
            preauth_integrity_hash_id: HashAlgorithm::SHA512,
            posix_extension_payload: vec![],
            preauth_integrity_hash_value: vec![],
            cipher_id: EncryptionCipher::None,
            client_dialects: vec![],
            compression_ids: vec![],
            supports_chained_compression: false,
            rdma_transform_ids: vec![],
            signing_algorithm_id: SigningAlgorithm::HmacSha256,
            accept_transport_security: false,
            underlying_stream: Arc::new(Mutex::new(value.0)),
            server: value.1
        })
    }
}