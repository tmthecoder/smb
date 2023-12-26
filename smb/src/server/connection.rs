use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::mpsc::Sender;

use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use uuid::Uuid;

use smb_core::error::SMBError;
use smb_core::SMBResult;

use crate::protocol::body::{Capabilities, FileTime, SMBBody, SMBDialect};
use crate::protocol::body::negotiate::{CompressionAlgorithm, NegotiateSecurityMode, RDMATransformID, SMBNegotiateResponse};
use crate::protocol::body::session_setup::SMBSessionSetupResponse;
use crate::protocol::body::tree_connect::SMBTreeConnectResponse;
use crate::protocol::header::{Header, SMBCommandCode, SMBFlags, SMBSyncHeader};
use crate::protocol::message::{Message, SMBMessage};
use crate::server::request::Request;
use crate::server::server::SMBServerDiagnosticsUpdate;
use crate::server::session::Session;
use crate::server::SMBPreauthSession;
use crate::socket::message_stream::{SMBReadStream, SMBSocketConnection, SMBWriteStream};
use crate::util::auth::{AuthProvider, User};
use crate::util::auth::nt_status::NTStatus;
use crate::util::auth::ntlm::{NTLMAuthContext, NTLMAuthProvider, NTLMMessage};
use crate::util::auth::spnego::{SPNEGOToken, SPNEGOTokenInitBody, SPNEGOTokenResponseBody};

// use tokio::sync::Mutex;
// use tokio_stream::StreamExt;

pub trait Connection: Debug {}

#[derive(Debug)]
pub struct SMBConnection<R: SMBReadStream, W: SMBWriteStream> {
    command_sequence_window: Vec<u32>,
    request_list: HashMap<u64, Box<dyn Request>>,
    client_capabilities: Capabilities,
    negotiate_dialect: SMBDialect,
    async_command_list: HashMap<u64, Box<dyn Request>>,
    dialect: SMBDialect,
    should_sign: bool,
    client_name: String,
    max_transact_size: u64,
    max_write_size: u64,
    max_read_size: u64,
    supports_multi_credit: bool,
    transport_name: String,
    session_table: HashMap<u64, Box<dyn Session>>,
    creation_time: FileTime,
    preauth_session_table: HashMap<u64, SMBPreauthSession>, // TODO
    clint_guid: Uuid,
    server_capabilites: Capabilities,
    client_security_mode: NegotiateSecurityMode,
    server_security_mode: NegotiateSecurityMode,
    constrained_connection: bool,
    preauth_integrity_hash_id: u64, // TODO
    preauth_integrity_hash_value: Vec<u8>, // TODO
    cipher_id: u64,
    client_dialects: Vec<SMBDialect>,
    compression_ids: Vec<CompressionAlgorithm>, // TODO ??
    supports_chained_compression: bool,
    rdma_transform_ids: Vec<RDMATransformID>, // TODO ??
    signing_algorithm_id: u64,
    accept_transport_security: bool,
    underlying_stream: Arc<Mutex<SMBSocketConnection<R, W>>>,
}

impl<R: SMBReadStream, W: SMBWriteStream> SMBConnection<R, W> {
    pub fn name(&self) -> &str {
        &self.client_name
    }

    pub fn underlying_socket(&self) -> Arc<Mutex<SMBSocketConnection<R, W>>> {
        self.underlying_stream.clone()
    }

    pub async fn start_message_handler(stream: &mut SMBSocketConnection<R, W>, update_channel: Sender<SMBServerDiagnosticsUpdate>) -> SMBResult<()> {
        let mut ctx = NTLMAuthContext::new();
        let (read, write) = stream.streams();
        println!("Start message handler");
        while let Some(message) = read.messages().next().await {
            let message = match message.header.command_code() {
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
                    Ok(SMBMessage::new(resp_header, resp_body))
                }
                SMBCommandCode::Negotiate => {
                    if let SMBBody::NegotiateRequest(request) = message.body {
                        let init_buffer = SPNEGOToken::Init(SPNEGOTokenInitBody::<NTLMAuthProvider>::new());
                        let neg_resp = SMBNegotiateResponse::from_request(request, init_buffer.as_bytes(true))
                            .unwrap();
                        let resp_body = SMBBody::NegotiateResponse(neg_resp);
                        let resp_header = message.header.create_response_header(0x0, 0);
                        Ok(SMBMessage::new(resp_header, resp_body))
                    } else {
                        Err(SMBError::response_error("Invalid Negotiate Payload"))
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
                                let mech_token = init_msg.mech_token.ok_or(SMBError::parse_error("Parse failure"))?;
                                let ntlm_msg =
                                    NTLMMessage::parse(&mech_token).map_err(|_e| SMBError::parse_error("Parse failure"))?.1;
                                helper.accept_security_context(&ntlm_msg, &mut ctx)
                            }
                            SPNEGOToken::Response(resp_msg) => {
                                let response_token = resp_msg.response_token.ok_or(SMBError::parse_error("Parse failure"))?;
                                let ntlm_msg =
                                    NTLMMessage::parse(&response_token).map_err(|_e| SMBError::parse_error("Parse failure"))?.1;
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
                let _ = update_channel.send(SMBServerDiagnosticsUpdate::default().bytes_sent(sent as u64));
            }
        }

        // Close streams on message parse finish (logoff)
        // let _ = read.shutdown(Shutdown::Both);
        Ok(())
    }
}

impl<R: SMBReadStream, W: SMBWriteStream> TryFrom<SMBSocketConnection<R, W>> for SMBConnection<R, W> {
    type Error = SMBError;

    fn try_from(value: SMBSocketConnection<R, W>) -> Result<Self, Self::Error> {
        let client_name = value.name().to_string();
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
            clint_guid: Default::default(),
            server_capabilites: Capabilities::empty(),
            client_security_mode: NegotiateSecurityMode::empty(),
            server_security_mode: NegotiateSecurityMode::empty(),
            constrained_connection: false,
            preauth_integrity_hash_id: 0,
            preauth_integrity_hash_value: vec![],
            cipher_id: 0,
            client_dialects: vec![],
            compression_ids: vec![],
            supports_chained_compression: false,
            rdma_transform_ids: vec![],
            signing_algorithm_id: 0,
            accept_transport_security: false,
            underlying_stream: Arc::new(Mutex::new(value)),
        })
    }
}