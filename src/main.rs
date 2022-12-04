use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;
use cross_krb5::{AcceptFlags, ServerCtx, Step};
// use libgssapi::context::ServerCtx;
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{GSS_MA_NEGOEX_AND_SPNEGO, GSS_MECH_IAKERB, GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE, GSS_NT_USER_NAME, Oid, OidSet};
use smb_reader::message::{Message, SMBMessage};
use smb_reader::protocol::body::{Capabilities, FileTime, SecurityMode, SMBBody, SMBDialect, SMBSessionSetupResponse};
use smb_reader::protocol::body::negotiate::SMBNegotiateResponse;
use smb_reader::protocol::header::{SMBCommandCode, SMBFlags, SMBSyncHeader};
use smb_reader::SMBListener;

pub static SPNEGO_MECH: Oid = Oid::from_slice(b"\x2b\x06\x01\x05\x05\x02");
pub static NTLM_MECH: Oid = Oid::from_slice(b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a");
pub static KRB5_MECH: Oid = Oid::from_slice(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02");

fn main() -> anyhow::Result<()> {
    let server = SMBListener::new("127.0.0.1:50122");
    let start_time = FileTime::now();
    for mut connection in server.unwrap().connections() {
        let mut cloned_connection = connection.try_clone()?;
        let desired_mechs = {
            let mut s = OidSet::new().unwrap();
            s.add(&GSS_MECH_KRB5).unwrap();
            // s.add(&NTLM_MECH).unwrap();
            // s.add(&SPNEGO_MECH).unwrap();
            s
        };
        // let mut server_sock = TcpStream::connect("127.0.0.1:50124").unwrap();
        let name = Name::new("tejasmehta".as_bytes(), Some(&GSS_NT_HOSTBASED_SERVICE)).unwrap();
        let cred = Cred::acquire(
            Some(&name), None, CredUsage::Accept, None
        ).unwrap();
        // let mut token_len_buf = [0_u8; 4];
        // server_sock.read_exact(&mut token_len_buf).unwrap();
        // let mut token_buf = vec![0; u32::from_be_bytes(token_len_buf) as usize];
        // server_sock.read_exact(&mut *token_buf).unwrap();
        let mut server = ServerCtx::new(AcceptFlags::empty(), Some("server@EXAMPLE.COM")).expect("new");
        // let mut server_ctx = ServerCtx::new(cred);
       for message in connection.messages() {
           match message.header.command {
               SMBCommandCode::LegacyNegotiate => {
                   let resp_body = SMBBody::NegotiateResponse(SMBNegotiateResponse::new(SecurityMode::empty(), SMBDialect::V2_X_X, Capabilities::empty(), 100, 100, 100, start_time.clone(), Vec::new()));
                   let resp_header = SMBSyncHeader::new(SMBCommandCode::Negotiate, SMBFlags::SERVER_TO_REDIR, 0, 0, 65535, 65535, [0; 16]);
                   let resp_msg = SMBMessage::new(resp_header, resp_body);
                   cloned_connection.send_message(resp_msg)?;
               }
               SMBCommandCode::Negotiate => {
                   if let SMBBody::NegotiateRequest(request) = message.body {
                       let post_action = server.step(&[]).unwrap();
                       let token;
                       match post_action {
                           Step::Continue((ctx, t)) => {
                               token = t.to_vec();
                               server = ctx;
                           },
                           Step::Finished((ctx, t)) => {
                               token = t.unwrap().to_vec();
                               break;
                           }
                       }
                       let resp_body = SMBBody::NegotiateResponse(SMBNegotiateResponse::from_request(request, token).unwrap());
                       let resp_header = message.header.create_response_header(0x0);
                       let resp_msg = SMBMessage::new(resp_header, resp_body);
                       cloned_connection.send_message(resp_msg)?;
                   }
               }
               SMBCommandCode::SessionSetup => {
                   if let SMBBody::SessionSetupRequest(request) = message.body {
                       let post_action = server.step(&request.get_buffer_copy()).unwrap();
                       let token;
                       let status;
                       match post_action {
                           Step::Continue((ctx, t)) => {
                               token = t.to_vec();
                               status = 0xC0000016;
                               server = ctx;
                           },
                           Step::Finished((ctx, t)) => {
                               token = t.unwrap().to_vec();
                               status = 0x0;
                               break;
                           }
                       }
                       let resp = SMBSessionSetupResponse::from_request(request, token).unwrap();
                       let resp_body = SMBBody::SessionSetupResponse(resp);
                       let resp_header = message.header.create_response_header(status);
                       let resp_msg = SMBMessage::new(resp_header, resp_body);
                       println!("MSG: {:?}", resp_msg);
                       println!("BYTES: {:?}", resp_msg.as_bytes());
                       cloned_connection.send_message(resp_msg)?;
                   }
               }
               _ => {}
           }
           if message.header.command != SMBCommandCode::Negotiate {
               continue;
           }

       }
    }
    Ok(())
}