use crate::protocol::body::FileTime;
use crate::protocol::body::tree_connect::SMBAccessMask;
use crate::server::session::SMBSession;
use crate::server::share::SharedResource;
use crate::socket::message_stream::{SMBReadStream, SMBWriteStream};

pub struct SMBTreeConnect<T: SharedResource, R: SMBReadStream, W: SMBWriteStream> {
    tree_id: u32,
    session: SMBSession<T, R, W>,
    share: T,
    open_count: u64,
    tree_global_id: u64,
    creation_time: FileTime,
    maximal_access: SMBAccessMask,
    remoted_identity_security_context: Vec<u8> // TODO
}