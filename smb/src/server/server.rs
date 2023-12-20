use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};

use uuid::Uuid;

use smb_core::error::SMBError;
use smb_core::SMBToBytes;

use crate::protocol::body::{Capabilities, FileTime, SMBBody, SMBDialect};
use crate::protocol::body::negotiate::{NegotiateSecurityMode, SMBNegotiateResponse};
use crate::protocol::body::session_setup::SMBSessionSetupResponse;
use crate::protocol::body::tree_connect::SMBTreeConnectResponse;
use crate::protocol::header::{Header, SMBCommandCode, SMBFlags, SMBSyncHeader};
use crate::protocol::message::SMBMessage;
use crate::server::{SMBClient, SMBLeaseTable};
use crate::server::connection::Connection;
use crate::server::open::Open;
use crate::server::session::Session;
use crate::server::share::SharedResource;
use crate::SMBListener;
use crate::util::auth::{AuthProvider, User};
use crate::util::auth::nt_status::NTStatus;
use crate::util::auth::ntlm::{NTLMAuthContext, NTLMAuthProvider, NTLMMessage};
use crate::util::auth::spnego::{SPNEGOToken, SPNEGOTokenInitBody, SPNEGOTokenResponseBody};

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
    local_listener: SMBListener
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
    address: Vec<SocketAddr>,
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
            address: ToSocketAddrs::to_socket_addrs("127.0.0.1:445").unwrap().collect()
        }
    }
}

impl SMBServerBuilder {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn add_share(&mut self, name: String, share: Box<dyn SharedResource>) -> &mut Self {
        self.share_list.insert(name, share);
        self
    }

    pub fn set_guid(&mut self, guid: Uuid) -> &mut Self {
        self.guid = guid;
        self
    }

    pub fn set_copy_max_chunks(&mut self, copy_max_chunks: u64) -> &mut Self {
        self.copy_max_chunks = copy_max_chunks;
        self
    }

    pub fn set_copy_max_chunk_size(&mut self, copy_max_chunk_size: u64) -> &mut Self {
        self.copy_max_chunk_size = copy_max_chunk_size;
        self
    }

    pub fn set_copy_max_data_size(&mut self, copy_max_data_size: u64) -> &mut Self {
        self.copy_max_data_size = copy_max_data_size;
        self
    }

    pub fn set_hash_level(&mut self, hash_level: HashLevel) -> &mut Self {
        self.hash_level = hash_level;
        self
    }

    pub fn set_max_resiliency_timeout(&mut self, max_resiliency_timeout: u64) -> &mut Self {
        self.max_resiliency_timeout = max_resiliency_timeout;
        self
    }

    pub fn encrypts_data(&mut self, encrypt_data: bool) -> &mut Self {
        self.encrypt_data = encrypt_data;
        self
    }

    pub fn allows_unencrypted_access(&mut self, unencrypted_access: bool) -> &mut Self {
        self.unencrypted_access = unencrypted_access;
        self
    }

    pub fn is_multi_channel_capable(&mut self, multi_channel_capable: bool) -> &mut Self {
        self.multi_channel_capable = multi_channel_capable;
        self
    }

    pub fn set_max_cluster_dialect(&mut self, max_cluster_dialect: SMBDialect) -> &mut Self {
        self.max_cluster_dialect = max_cluster_dialect;
        self
    }

    pub fn supports_tree_connect_extension(&mut self, tree_connect_extension: bool) -> &mut Self {
        self.tree_connect_extension = tree_connect_extension;
        self
    }

    pub fn allows_anonymous_access(&mut self, anonymous_access: bool) -> &mut Self {
        self.anonymous_access = anonymous_access;
        self
    }

    pub fn allows_named_pipe_access_over_quic(&mut self, named_pipe_access_over_quic: bool) -> &mut Self {
        self.named_pipe_access_over_quic = named_pipe_access_over_quic;
        self
    }

    pub fn set_address<A: ToSocketAddrs>(&mut self, address: A) -> &mut Self {
        self.address = address.to_socket_addrs().unwrap().collect();
        self
    }

    pub fn build(self) -> SMBServer {
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
            local_listener: SMBListener::new(&*self.address).unwrap()
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

    pub fn start(&mut self) -> anyhow::Result<()> {
        let mut ctx = NTLMAuthContext::new();
        for mut connection in self.local_listener.connections() {
            let mut cloned_connection = connection.try_clone()?;
            for message in connection.messages() {
                match message.header.command_code() {
                    SMBCommandCode::LegacyNegotiate => {
                        let resp_body = SMBBody::NegotiateResponse(SMBNegotiateResponse::new(
                            NegotiateSecurityMode::empty(),
                            SMBDialect::V2_X_X,
                            Capabilities::empty(),
                            100,
                            100,
                            100,
                            FileTime::default(),
                            Vec::new(),
                        ));
                        let resp_header = SMBSyncHeader::new(
                            SMBCommandCode::Negotiate,
                            SMBFlags::SERVER_TO_REDIR,
                            0,
                            0,
                            65535,
                            65535,
                            [0; 16],
                        );
                        let resp_msg = SMBMessage::new(resp_header, resp_body);
                        cloned_connection.send_message(resp_msg)?;
                    }
                    SMBCommandCode::Negotiate => {
                        if let SMBBody::NegotiateRequest(request) = message.body {
                            let init_buffer = SPNEGOToken::Init(SPNEGOTokenInitBody::<NTLMAuthProvider>::new());
                            let neg_resp = SMBNegotiateResponse::from_request(request, init_buffer.as_bytes(true))
                                .unwrap();
                            let resp_body = SMBBody::NegotiateResponse(neg_resp);
                            let resp_header = message.header.create_response_header(0x0, 0);
                            let resp_msg = SMBMessage::new(resp_header, resp_body);
                            cloned_connection.send_message(resp_msg)?;
                        }
                    }
                    SMBCommandCode::SessionSetup => {
                        if let SMBBody::SessionSetupRequest(request) = message.body {
                            let spnego_init_buffer: SPNEGOToken<NTLMAuthProvider> =
                                SPNEGOToken::parse(&request.get_buffer_copy()).unwrap().1;
                            println!("SPNEGOBUFFER: {:?}", spnego_init_buffer);
                            let helper = NTLMAuthProvider::new(
                                vec![User::new("tejasmehta".into(), "password".into())],
                                true,
                            );
                            let (status, output) = match spnego_init_buffer {
                                SPNEGOToken::Init(init_msg) => {
                                    let mech_token = init_msg.mech_token.ok_or(SMBError::ParseError("Parse failure"))?;
                                    let ntlm_msg =
                                        NTLMMessage::parse(&mech_token).map_err(|_e| SMBError::ParseError("Parse failure"))?.1;
                                    helper.accept_security_context(&ntlm_msg, &mut ctx)
                                }
                                SPNEGOToken::Response(resp_msg) => {
                                    let response_token = resp_msg.response_token.ok_or(SMBError::ParseError("Parse failure"))?;
                                    let ntlm_msg =
                                        NTLMMessage::parse(&response_token).map_err(|_e| SMBError::ParseError("Parse failure"))?.1;
                                    println!("NTLM: {:?}", ntlm_msg);
                                    helper.accept_security_context(&ntlm_msg, &mut ctx)
                                }
                                _ => { (NTStatus::StatusSuccess, NTLMMessage::Dummy) }
                            };
                            println!("status: {:?}, output: {:?}", status, output);
                            let spnego_response_body = SPNEGOTokenResponseBody::<NTLMAuthProvider>::new(status.clone(), output);
                            let resp = SMBSessionSetupResponse::from_request(
                                request,
                                spnego_response_body.as_bytes(),
                            ).unwrap();
                            println!("Test response: {:?}", resp.smb_to_bytes());
                            println!("Actu response: {:?}", resp.as_bytes());
                            let resp_body = SMBBody::SessionSetupResponse(resp);
                            let resp_header = message.header.create_response_header(0, 1010);
                            let resp_msg = SMBMessage::new(resp_header, resp_body);

                            cloned_connection.send_message(resp_msg)?;
                        }
                    },
                    SMBCommandCode::TreeConnect => {
                        println!("Got tree connect");
                        if let SMBBody::TreeConnectRequest(request) = message.body {
                            println!("Tree connect request: {:?}", request);
                            let resp_body = match request.path().contains("IPC$") {
                                true => SMBBody::TreeConnectResponse(SMBTreeConnectResponse::IPC()),
                                false => SMBBody::TreeConnectResponse(SMBTreeConnectResponse::default()),
                            };
                            let resp_header = message.header.create_response_header(0, 1010);
                            let resp_msg = SMBMessage::new(resp_header, resp_body);

                            cloned_connection.send_message(resp_msg)?;
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
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