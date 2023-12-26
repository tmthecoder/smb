use crate::server::SMBConnection;
use crate::socket::message_stream::{SMBReadStream, SMBWriteStream};

pub struct SMBChannel<R: SMBReadStream, W: SMBWriteStream> {
    signing_key: [u8; 16],
    connection: SMBConnection<R, W>
}