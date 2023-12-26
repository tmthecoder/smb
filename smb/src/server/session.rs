use std::collections::HashMap;
use std::fmt::Debug;

use crate::server::{SMBChannel, SMBOpen, SMBTreeConnect};
use crate::server::share::SharedResource;
use crate::socket::message_stream::{SMBReadStream, SMBWriteStream};
use crate::util::auth::AuthContext;

pub trait Session: Debug + Send + Sync {}

pub struct SMBSession<T: SharedResource, R: SMBReadStream, W: SMBWriteStream> {
    session_id: u64,
    state: SessionState,
    security_context: AuthContext,
    // TODO >>
    is_anonymous: bool,
    is_guest: bool,
    session_key: [u8; 16],
    signing_required: bool,
    open_table: HashMap<u64, SMBOpen<T, R, W>>,
    tree_connect_table: HashMap<u64, SMBTreeConnect<T, R, W>>,
    expiration_time: u64,
    connection: T,
    global_id: u32,
    creation_time: u64,
    idle_time: u64,
    user_name: String,
    channel_list: HashMap<u64, SMBChannel<R, W>>,
    encrypt_data: bool,
    encryption_key: Vec<u8>,
    decryption_key: Vec<u8>,
    signing_key: Vec<u8>,
    application_key: Vec<u8>,
    pre_auth_integrity_hash_value: Vec<u8>,
    full_session_key: Vec<u8>
}

pub enum SessionState {
    InProgress,
    Valid,
    Expired
}