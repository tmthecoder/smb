use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::sync::{Arc, Weak};

use derive_builder::Builder;
use tokio::sync::{Mutex, RwLock};
use tokio::sync::mpsc::Sender;
use tokio_stream::StreamExt;
use uuid::Uuid;

use smb_core::error::SMBError;
use smb_core::SMBResult;

use crate::protocol::body::capabilities::Capabilities;
use crate::protocol::body::dialect::SMBDialect;
use crate::protocol::body::filetime::FileTime;
use crate::protocol::body::negotiate::context::{CompressionAlgorithm, EncryptionCipher, HashAlgorithm, RDMATransformID, SigningAlgorithm};
use crate::protocol::body::negotiate::security_mode::NegotiateSecurityMode;
use crate::protocol::body::negotiate::SMBNegotiateResponse;
use crate::protocol::body::session_setup::SMBSessionSetupResponse;
use crate::protocol::body::SMBBody;
use crate::protocol::body::tree_connect::SMBTreeConnectResponse;
use crate::protocol::header::{Header, SMBCommandCode, SMBFlags, SMBSyncHeader};
use crate::protocol::message::{Message, SMBMessage};
use crate::server::{Server, SMBServerDiagnosticsUpdate};
use crate::server::preauth_session::SMBPreauthSession;
use crate::server::request::Request;
use crate::server::session::Session;
use crate::socket::message_stream::{SMBReadStream, SMBSocketConnection, SMBWriteStream};
use crate::util::auth::{AuthContext, AuthMessage, AuthProvider};
use crate::util::auth::nt_status::NTStatus;
use crate::util::auth::ntlm::NTLMAuthProvider;
use crate::util::auth::spnego::{SPNEGOToken, SPNEGOTokenResponseBody};

// use tokio::sync::Mutex;
// use tokio_stream::StreamExt;

pub trait Connection: Debug {}

#[derive(Debug, Builder)]
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
    session_table: HashMap<u64, Box<dyn Session>>,
    creation_time: FileTime,
    preauth_session_table: HashMap<u64, SMBPreauthSession>, // TODO
    client_guid: Uuid,
    server_capabilites: Capabilities,
    client_security_mode: NegotiateSecurityMode,
    server_security_mode: NegotiateSecurityMode,
    constrained_connection: bool,
    preauth_integrity_hash_id: HashAlgorithm,
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
impl<R: SMBReadStream, W: SMBWriteStream, S: Server> SMBConnection<R, W, S> {
    pub fn client_capabilities(&self) -> Capabilities {
        self.client_capabilities
    }

    pub fn negotiate_dialect(&self) -> SMBDialect {
        self.negotiate_dialect
    }
    pub fn dialect(&self) -> SMBDialect {
        self.dialect
    }

    pub fn should_sign(&self) -> bool {
        self.should_sign
    }

    pub fn client_name(&self) -> &str {
        &self.client_name
    }
    pub fn max_transact_size(&self) -> u32 {
        self.max_transact_size
    }
    pub fn max_write_size(&self) -> u32 {
        self.max_write_size
    }

    pub fn max_read_size(&self) -> u32 {
        self.max_read_size
    }

    pub fn supports_multi_credit(&self) -> bool {
        self.supports_multi_credit
    }
    pub fn transport_name(&self) -> &str {
        &self.transport_name
    }

    pub fn client_guid(&self) -> Uuid {
        self.client_guid
    }

    pub fn server_capabilities(&self) -> Capabilities {
        self.server_capabilites
    }

    pub fn client_security_mode(&self) -> NegotiateSecurityMode {
        self.client_security_mode
    }
    pub fn server_security_mode(&self) -> NegotiateSecurityMode {
        self.server_security_mode
    }

    pub fn preauth_integrity_hash_id(&self) -> HashAlgorithm {
        self.preauth_integrity_hash_id
    }

    pub fn cipher_id(&self) -> EncryptionCipher {
        self.cipher_id
    }
    pub fn compression_ids(&self) -> &Vec<CompressionAlgorithm> {
        &self.compression_ids
    }
    pub fn supports_chained_compression(&self) -> bool {
        self.supports_chained_compression
    }

    pub fn rdma_transform_ids(&self) -> &Vec<RDMATransformID> {
        &self.rdma_transform_ids
    }
    pub fn signing_algorithm_id(&self) -> SigningAlgorithm {
        self.signing_algorithm_id
    }

    pub fn accept_transport_security(&self) -> bool {
        self.accept_transport_security
    }
    pub fn underlying_socket(&self) -> Arc<Mutex<SMBSocketConnection<R, W>>> {
        self.underlying_stream.clone()
    }
}

impl<R: SMBReadStream, W: SMBWriteStream, S: Server> SMBConnection<R, W, S> {
    pub async fn start_message_handler<A: AuthProvider>(stream: &mut SMBSocketConnection<R, W>, connection: Arc<RwLock<SMBConnection<R, W, S>>>, auth_provider: Arc<A>, update_channel: Sender<SMBServerDiagnosticsUpdate>) -> SMBResult<()> {
        let mut ctx = A::Context::init();
        let (read, write) = stream.streams();
        println!("Start message handler");
        let server = {
            connection.read().await.server.clone()
        };
        while let Some(message) = read.messages().next().await {
            println!("Got message: {:?}", message);
            let message = match message.header.command_code() {
                SMBCommandCode::LegacyNegotiate => connection.handle_legacy_negotiate(),
                SMBCommandCode::Negotiate => connection.handle_negotiate::<A>(&server, message).await,
                SMBCommandCode::SessionSetup => {
                    if let SMBBody::SessionSetupRequest(request) = message.body {
                        let spnego_init_buffer: SPNEGOToken<NTLMAuthProvider> =
                            SPNEGOToken::parse(&request.get_buffer_copy()).unwrap().1;
                        println!("SPNEGOBUFFER: {:?}", spnego_init_buffer);
                        let (status, output) = match spnego_init_buffer {
                            SPNEGOToken::Init(init_msg) => {
                                let mech_token = init_msg.mech_token.ok_or(SMBError::parse_error("Parse failure"))?;
                                let ntlm_msg =
                                    A::Message::parse(&mech_token).map_err(|_e| SMBError::parse_error("Parse failure"))?.1;
                                auth_provider.accept_security_context(&ntlm_msg, &mut ctx)
                            }
                            SPNEGOToken::Response(resp_msg) => {
                                let response_token = resp_msg.response_token.ok_or(SMBError::parse_error("Parse failure"))?;
                                let ntlm_msg =
                                    A::Message::parse(&response_token).map_err(|_e| SMBError::parse_error("Parse failure"))?.1;
                                auth_provider.accept_security_context(&ntlm_msg, &mut ctx)
                            }
                            _ => { (NTStatus::StatusSuccess, A::Message::empty()) }
                        };
                        // println!("status: {:?}, output: {:?}", status, output);
                        let spnego_response_body = SPNEGOTokenResponseBody::<A>::new(status.clone(), output);
                        let resp = SMBSessionSetupResponse::from_request(
                            request,
                            spnego_response_body.as_bytes(),
                        ).unwrap();
                        let resp_body = SMBBody::SessionSetupResponse(resp);
                        let resp_header = message.header.create_response_header(0, 1010);
                        Ok(SMBMessage::new(resp_header, resp_body))
                    } else {
                        Err(SMBError::response_error("Invalid Session Setup Payload"))
                    }
                },
                SMBCommandCode::TreeConnect => {
                    if let SMBBody::TreeConnectRequest(request) = message.body {
                        println!("Tree connect request: {:?}", request);
                        let resp_body = match request.path().contains("IPC$") {
                            true => SMBBody::TreeConnectResponse(SMBTreeConnectResponse::IPC()),
                            false => SMBBody::TreeConnectResponse(SMBTreeConnectResponse::default()),
                        };
                        let resp_header = message.header.create_response_header(0, 1010);
                        Ok(SMBMessage::new(resp_header, resp_body))
                    } else {
                        Err(SMBError::response_error("Invalid tree connect payload"))
                    }
                }
                SMBCommandCode::LogOff => {
                    println!("got logoff");
                    break;
                }
                _ => Err(SMBError::response_error("Invalid request payload"))
            };
            if let Ok(message) = message {
                let sent = write.write_message(&message).await?;
                let _ = update_channel.send(SMBServerDiagnosticsUpdate::default().bytes_sent(sent as u64)).await;
                ;
            }
        }

        // Close streams on message parse finish (logoff)
        let _ = write.close_stream().await;
        Ok(())
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
    }
}

type LockedSMBConnection<R, W, S> = Arc<RwLock<SMBConnection<R, W, S>>>;
type SMBMessageType = SMBMessage<SMBSyncHeader, SMBBody>;

impl<R: SMBReadStream, W: SMBWriteStream, S: Server> SMBLockedHandler<S> for LockedSMBConnection<R, W, S> {
    async fn handle_negotiate<A: AuthProvider>(&self, server: &Weak<RwLock<S>>, message: SMBMessageType) -> SMBResult<SMBMessageType> {
        let server = server.upgrade().ok_or(SMBError::response_error("No server available"))?;
        let unlocked = server.read().await;
        self.write().await.handle_negotiate::<A>(&unlocked, message)
    }
}

impl<R: SMBReadStream, W: SMBWriteStream, S: Server> SMBStatefulHandler<S> for SMBConnection<R, W, S> {
    fn handle_negotiate<A: AuthProvider>(&mut self, server: &S, message: SMBMessageType) -> SMBResult<SMBMessageType> {
        let SMBMessage { header, body } = message;
        if let SMBBody::NegotiateRequest(request) = body {
            let (update, contexts) = request.validate_and_set_state(self, server)?;
            self.apply_update(update);
            let resp_header = header.create_response_header(0x0, 0);
            let resp_body = SMBNegotiateResponse::from_connection_state::<A, R, W, S>(self, server, contexts);
            Ok(SMBMessage::new(resp_header, SMBBody::NegotiateResponse(resp_body)))
        } else {
            Err(SMBError::parse_error("Invalid SMB request body (expected NegotiateRequest)"))
        }
    }

    fn handle_session_setup(&mut self, server: S, message: SMBMessageType) -> SMBResult<SMBMessageType> {
        let SMBMessage { header, body } = message;
        if let SMBBody::SessionSetupRequest(request) = body {
            Err(SMBError::parse_error("Invalid SMB Request Body (expected SessionSetupRequest"))
        } else {
            Err(SMBError::parse_error("Invalid SMB Request Body (expected SessionSetupRequest"))
        }
    }
}

trait SMBLockedHandler<S: Server> {
    fn handle_legacy_negotiate(&self) -> SMBResult<SMBMessageType> {
        let resp_body = SMBBody::NegotiateResponse(SMBNegotiateResponse::legacy_response());
        let resp_header = SMBSyncHeader::new(
            SMBCommandCode::Negotiate,
            SMBFlags::SERVER_TO_REDIR,
            0,
            0,
            65535,
            65535,
            [0; 16],
        );
        Ok(SMBMessage::new(resp_header, resp_body))
    }

    fn handle_negotiate<A: AuthProvider>(&self, server: &Weak<RwLock<S>>, message: SMBMessageType) -> impl Future<Output=SMBResult<SMBMessageType>>;
}

trait SMBStatefulHandler<S: Server> {
    fn handle_negotiate<A: AuthProvider>(&mut self, server: &S, message: SMBMessageType) -> SMBResult<SMBMessageType>;
    fn handle_session_setup(&mut self, server: S, message: SMBMessageType) -> SMBResult<SMBMessageType>;
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