use std::collections::HashMap;
use std::net::ToSocketAddrs;

use derive_builder::Builder;
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

#[derive(Debug, Builder)]
#[builder(pattern = "owned")]
pub struct SMBServer {
    #[builder(default = "ServerDiagnostics::new()")]
    statistics: ServerDiagnostics,
    #[builder(default = "false")]
    enabled: bool,
    #[builder(default = "HashMap::new()")]
    share_list: HashMap<String, Box<dyn SharedResource>>,
    #[builder(default = "HashMap::new()")]
    open_table: HashMap<u64, Box<dyn Open>>,
    #[builder(default = "HashMap::new()")]
    session_table: HashMap<u64, Box<dyn Session>>,
    #[builder(default = "HashMap::new()")]
    connection_list: HashMap<u64, Box<dyn Connection>>,
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
    #[builder(default = "HashMap::new()")]
    lease_table_list: HashMap<Uuid, SMBLeaseTable>,
    #[builder(default = "5000")]
    max_resiliency_timeout: u64,
    #[builder(default = "5000")]
    resilient_open_scavenger_expiry_time: u64,
    #[builder(default = "HashMap::new()")]
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
    local_listener: SMBListener
}

impl SMBServerBuilder {
    pub fn listener_address<S: ToSocketAddrs>(self, addr: S) -> std::io::Result<Self> {
        Ok(self.local_listener(SMBListener::new(addr)?))
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
    pub fn initialize(&mut self) {
        self.statistics = ServerDiagnostics::new();
        self.guid = Uuid::new_v4();
        // *self = Self::new()
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
                    SMBCommandCode::LogOff => {
                        break;
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
    big_buffer_need: u32,
}

impl ServerDiagnostics {
    pub fn new() -> Self {
        Default::default()
    }
}