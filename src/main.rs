use smb_reader::body::{Capabilities, FileTime, SecurityMode, SMBBody, SMBDialect, SMBNegotiationResponse, SMBSessionSetupResponse};
use smb_reader::header::{SMBCommandCode, SMBFlags, SMBSyncHeader};
use smb_reader::message::{Message, SMBMessage};
use smb_reader::SMBServer;

fn main() -> anyhow::Result<()> {
    let server = SMBServer::new("127.0.0.1:50122");
    let start_time = FileTime::now();
    for mut connection in server.unwrap().connections() {
        let mut cloned_connection = connection.try_clone()?;
       for message in connection.messages() {
           println!("Message: {:?}", message);
           match message.header.command {
               SMBCommandCode::LegacyNegotiate => {
                   let resp_body = SMBBody::NegotiateResponse(SMBNegotiationResponse::new(SecurityMode::NEGOTIATE_SIGNING_ENABLED, SMBDialect::V2_X_X, Capabilities::empty(), 100, 100, 100, start_time.clone(), Vec::new()));
                   let resp_header = SMBSyncHeader::new(SMBCommandCode::Negotiate, SMBFlags::SERVER_TO_REDIR, 0, 0, 65535, 65535, [0; 16]);
                   let resp_msg = SMBMessage::new(resp_header, resp_body);
                   println!("resp: {:?} bytes: {:?}", resp_msg, resp_msg.as_bytes());
                   cloned_connection.send_message(resp_msg)?;
               }
               SMBCommandCode::Negotiate => {
                   if let SMBBody::NegotiateRequest(request) = message.body {
                       let resp_body = SMBBody::NegotiateResponse(SMBNegotiationResponse::from_request(request).unwrap());
                       let resp_header = message.header.create_response_header();
                       let resp_msg = SMBMessage::new(resp_header, resp_body);
                       cloned_connection.send_message(resp_msg)?;
                   }
               }
               SMBCommandCode::SessionSetup => {
                   if let SMBBody::SessionSetupRequest(request) = message.body {
                       let resp_body = SMBBody::SessionSetupResponse(SMBSessionSetupResponse::from_request(request).unwrap());
                       let resp_header = message.header.create_response_header();
                       let resp_msg = SMBMessage::new(resp_header, resp_body);
                       println!("MSG: {:?}", resp_msg);
                       println!("BYTES: {:?}", resp_msg.as_bytes());
                       cloned_connection.send_message(resp_msg)?;                   }
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