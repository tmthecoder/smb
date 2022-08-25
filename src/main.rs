use smb_reader::{SMBMessageCommandCode, SMBServer};
fn main() {
    let server = SMBServer::new("127.0.0.1:50122");
    for mut connection in server.unwrap().connections() {
        let vec = connection.messages().map(|msg| println!("Message {:?}", msg)).collect::<Vec<()>>();
    }
}