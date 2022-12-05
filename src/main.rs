use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;
use smb_reader::message::{Message, SMBMessage};
use smb_reader::protocol::body::{Capabilities, FileTime, SecurityMode, SMBBody, SMBDialect, SMBSessionSetupResponse};
use smb_reader::protocol::body::negotiate::SMBNegotiateResponse;
use smb_reader::protocol::header::{SMBCommandCode, SMBFlags, SMBSyncHeader};
use smb_reader::SMBListener;

fn main() -> anyhow::Result<()> {
    let server = SMBListener::new("127.0.0.1:50122");
    let start_time = FileTime::now();
    for mut connection in server.unwrap().connections() {
        let mut cloned_connection = connection.try_clone()?;
        // let mut server_sock = TcpStream::connect("127.0.0.1:50124").unwrap();
        // let mut token_len_buf = [0_u8; 4];
        // server_sock.read_exact(&mut token_len_buf).unwrap();
        // let mut token_buf = vec![0; u32::from_be_bytes(token_len_buf) as usize];
        // server_sock.read_exact(&mut *token_buf).unwrap();
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
                       let resp_body = SMBBody::NegotiateResponse(SMBNegotiateResponse::from_request(request, Vec::new()).unwrap());
                       let resp_header = message.header.create_response_header(0x0);
                       let resp_msg = SMBMessage::new(resp_header, resp_body);
                       cloned_connection.send_message(resp_msg)?;
                   }
               }
               SMBCommandCode::SessionSetup => {
                   if let SMBBody::SessionSetupRequest(request) = message.body {
                       let resp = SMBSessionSetupResponse::from_request(request, Vec::new()).unwrap();
                       let resp_body = SMBBody::SessionSetupResponse(resp);
                       let resp_header = message.header.create_response_header(0);
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