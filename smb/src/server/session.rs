use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, RwLock};

use crate::server::channel::SMBChannel;
use crate::server::connection::SMBConnection;
use crate::server::open::Open;
use crate::server::Server;
use crate::server::tree_connect::TreeConnect;
use crate::socket::message_stream::{SMBReadStream, SMBWriteStream};
use crate::util::auth::GenericAuthContext;

pub trait Session: Debug + Send + Sync {}

pub struct SMBSession<R: SMBReadStream, W: SMBWriteStream, S: Server> {
    session_id: u64,
    state: SessionState,
    security_context: GenericAuthContext,
    // TODO >>
    is_anonymous: bool,
    is_guest: bool,
    session_key: [u8; 16],
    signing_required: bool,
    open_table: HashMap<u64, Box<dyn Open>>,
    tree_connect_table: HashMap<u64, Box<dyn TreeConnect>>,
    expiration_time: u64,
    connection: Arc<RwLock<SMBConnection<R, W, S>>>,
    global_id: u32,
    creation_time: u64,
    idle_time: u64,
    user_name: String,
    channel_list: HashMap<u64, SMBChannel<R, W, S>>,
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