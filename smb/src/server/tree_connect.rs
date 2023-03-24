use crate::body::FileTime;
use crate::server::session::SMBSession;
use crate::server::SMBShare;

pub struct SMBTreeConnect {
    tree_id: u32,
    session: SMBSession,
    share: SMBShare,
    open_count: u64,
    tree_global_id: u64,
    creation_time: FileTime,
    maximal_access: ??,
    remoted_identity_security_context: ??
}