use crate::server::{Server, SMBConnection};
use crate::socket::message_stream::{SMBReadStream, SMBWriteStream};

pub struct SMBChannel<R: SMBReadStream, W: SMBWriteStream, S: Server> {
    signing_key: [u8; 16],
    connection: SMBConnection<R, W, S>
}

