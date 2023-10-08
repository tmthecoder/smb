use smb_core::{error::SMBError, SMBToBytes};
use smb_reader::protocol::body::{Body, Capabilities, FileTime, SMBBody, SMBDialect};
use smb_reader::protocol::body::negotiate::{NegotiateSecurityMode, SMBNegotiateResponse};
use smb_reader::protocol::body::session_setup::SMBSessionSetupResponse;
use smb_reader::protocol::header::{Header, SMBCommandCode, SMBFlags, SMBSyncHeader};
use smb_reader::protocol::message::SMBMessage;
use smb_reader::SMBListener;
use smb_reader::util::auth::{AuthProvider, User};
use smb_reader::util::auth::nt_status::NTStatus;
use smb_reader::util::auth::ntlm::{NTLMAuthContext, NTLMAuthProvider, NTLMMessage};
use smb_reader::util::auth::spnego::{SPNEGOToken, SPNEGOTokenInitBody, SPNEGOTokenResponseBody};

const NTLM_ID: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
const SPNEGO_ID: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

fn main() -> anyhow::Result<()> {
    let server = SMBListener::new("127.0.0.1:50122")?;
    let start_time = FileTime::now();
    let mut ctx = NTLMAuthContext::new();
    for mut connection in server.connections() {
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
                        start_time.clone(),
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
                        println!("Test to bytes: {:?}, {:?}", message.header.smb_to_bytes(), request.smb_to_bytes());
                        let init_buffer = SPNEGOToken::Init(SPNEGOTokenInitBody::<NTLMAuthProvider>::new());
                        let neg_resp = SMBNegotiateResponse::from_request(request, init_buffer.as_bytes(true))
                            .unwrap();
                        println!("New rp: {:02x?}", neg_resp.smb_to_bytes());
                        println!("Actual: {:02x?}", neg_resp.as_bytes());
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
                            vec![User::new("tejasmehta".into(), "Password".into())],
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
                }
                _ => {}
            }
        }
    }
    Ok(())
}