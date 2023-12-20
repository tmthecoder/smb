use crate::server::share::SharedResource;
use crate::server::SMBConnection;

pub struct SMBChannel<T: SharedResource> {
    signing_key: [u8; 16],
    connection: SMBConnection<T>
}