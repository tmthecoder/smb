use libgssapi::context::ServerCtx;
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{GSS_MECH_IAKERB, GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE, OidSet};
use smb_reader::body::{Capabilities, FileTime, SecurityMode, SMBBody, SMBDialect, SMBNegotiationResponse, SMBSessionSetupResponse};
use smb_reader::header::{SMBCommandCode, SMBFlags, SMBSyncHeader};
use smb_reader::message::{Message, SMBMessage};
use smb_reader::SMBListener;

fn main() -> anyhow::Result<()> {
    let server = SMBListener::new("127.0.0.1:50122");
    let start_time = FileTime::now();
    for mut connection in server.unwrap().connections() {
        let mut cloned_connection = connection.try_clone()?;
       for message in connection.messages() {
           println!("Message: {:?}", message);
           let desired_mechs = {
               let mut s = OidSet::new().unwrap();
               s.add(&GSS_MECH_KRB5).unwrap();
               s
           };
           let name = Name::new("tejasmehta".as_bytes(), Some(&GSS_NT_HOSTBASED_SERVICE)).unwrap();
           let cred = Cred::acquire(
               Some(&name), None, CredUsage::Accept, None
           ).unwrap();

           let mut server_ctx = ServerCtx::new(cred);
           match message.header.command {
               SMBCommandCode::LegacyNegotiate => {
                   let resp_body = SMBBody::NegotiateResponse(SMBNegotiationResponse::new(SecurityMode::NEGOTIATE_SIGNING_ENABLED, SMBDialect::V2_X_X, Capabilities::empty(), 100, 100, 100, start_time.clone(), Vec::new()));
                   let resp_header = SMBSyncHeader::new(SMBCommandCode::Negotiate, SMBFlags::SERVER_TO_REDIR, 0, 0, 65535, 65535, [0; 16]);
                   let resp_msg = SMBMessage::new(resp_header, resp_body);
                   cloned_connection.send_message(resp_msg)?;
               }
               SMBCommandCode::Negotiate => {
                   if let SMBBody::NegotiateRequest(request) = message.body {
                       let resp_body = SMBBody::NegotiateResponse(SMBNegotiationResponse::from_request(request, &mut server_ctx).unwrap());
                       let resp_header = message.header.create_response_header();
                       let resp_msg = SMBMessage::new(resp_header, resp_body);
                       cloned_connection.send_message(resp_msg)?;
                   }
               }
               SMBCommandCode::SessionSetup => {
                   if let SMBBody::SessionSetupRequest(request) = message.body {
                       let resp_body = SMBBody::SessionSetupResponse(SMBSessionSetupResponse::from_request(request, &mut server_ctx).unwrap());
                       let resp_header = message.header.create_response_header();
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