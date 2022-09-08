use smb_reader::body::{Capabilities, FileTime, SecurityMode, SMBBody, SMBDialect, SMBNegotiationResponse};
use smb_reader::header::{SMBCommandCode, SMBFlags, SMBSyncHeader};
use smb_reader::message::SMBMessage;
use smb_reader::SMBServer;

fn main() -> anyhow::Result<()> {
    let server = SMBServer::new("127.0.0.1:50122");
    let start_time = FileTime::now();
    for mut connection in server.unwrap().connections() {
        let mut cloned_connection = connection.try_clone()?;
       for message in connection.messages() {
           println!("Message: {:?}", message);
           if message.header.command != SMBCommandCode::Negotiate {
               continue;
           }
           let resp_body = SMBBody::NegotiateResponse(SMBNegotiationResponse::new(SecurityMode::NEGOTIATE_SIGNING_ENABLED, SMBDialect::V2_0_2, Capabilities::empty(), 100, 100, 100, start_time.clone(), Vec::new()));
           let resp_header = SMBSyncHeader::new(SMBCommandCode::Negotiate, SMBFlags::empty(), 0, 0, 0, 0, [0; 16]);
           let message = SMBMessage::new(resp_header, resp_body);
           let size_snt = cloned_connection.send_message(message)?;
       }
    }
    Ok(())
}