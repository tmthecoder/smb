use crate::server::SMBConnection;

pub struct SMBChannel {
    signing_key: [u8; 16],
    connection: SMBConnection
}