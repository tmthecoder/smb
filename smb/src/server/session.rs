use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use derive_builder::Builder;
use tokio::sync::RwLock;

use crate::server::connection::Connection;
use crate::server::open::Open;
use crate::server::Server;
use crate::server::tree_connect::TreeConnect;
use crate::util::auth::{AuthContext, AuthProvider};

pub trait Session<C: Connection>: Send + Sync {
    fn init(id: u64, encrypt_data: bool, preauth_integrity_hash_value: Vec<u8>, conn: Arc<RwLock<C>>) -> Self;

    fn id(&self) -> u64;
    fn connection(&self) -> Arc<RwLock<C>>;
    fn state(&self) -> SessionState;
    fn anonymous(&self) -> bool;
    fn guest(&self) -> bool;
}

#[derive(Builder)]
#[builder(pattern = "owned")]
pub struct SMBSession<C: Connection, S: Server> {
    session_id: u64,
    state: SessionState,
    security_context: <S::AuthType as AuthProvider>::Context,
    // TODO >>
    is_anonymous: bool,
    is_guest: bool,
    session_key: [u8; 16],
    signing_required: bool,
    open_table: HashMap<u64, Box<dyn Open>>,
    tree_connect_table: HashMap<u64, Box<dyn TreeConnect>>,
    expiration_time: u64,
    connection: Arc<RwLock<C>>,
    global_id: u32,
    creation_time: u64,
    idle_time: u64,
    user_name: String,
    // channel_list: HashMap<u64, SMBChannel<R, W, S>>,
    encrypt_data: bool,
    encryption_key: Vec<u8>,
    decryption_key: Vec<u8>,
    signing_key: Vec<u8>,
    application_key: Vec<u8>,
    preauth_integrity_hash_value: Vec<u8>,
    full_session_key: Vec<u8>
}

impl<C: Connection, S: Server> Debug for SMBSession<C, S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SMBSession {{}}", )
    }
}

impl<C: Connection, S: Server> SMBSession<C, S> {}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum SessionState {
    InProgress,
    Valid,
    Expired
}

impl<C: Connection, S: Server> Session<C> for SMBSession<C, S> {
    fn init(id: u64, encrypt_data: bool, preauth_integrity_hash_value: Vec<u8>, conn: Arc<RwLock<C>>) -> Self {
        Self {
            session_id: id,
            state: SessionState::InProgress,
            security_context: <S::AuthType as AuthProvider>::Context::init(),
            is_anonymous: false,
            is_guest: false,
            session_key: [0; 16],
            signing_required: false,
            open_table: Default::default(),
            tree_connect_table: Default::default(),
            expiration_time: 0,
            connection: conn,
            global_id: 0,
            creation_time: 0,
            idle_time: 0,
            user_name: "".to_string(),
            encrypt_data,
            encryption_key: vec![],
            decryption_key: vec![],
            signing_key: vec![],
            application_key: vec![],
            preauth_integrity_hash_value,
            full_session_key: vec![],
        }
    }

    fn id(&self) -> u64 {
        self.session_id
    }

    fn connection(&self) -> Arc<RwLock<C>> {
        self.connection.clone()
    }

    fn state(&self) -> SessionState {
        self.state
    }

    fn anonymous(&self) -> bool {
        self.is_anonymous
    }

    fn guest(&self) -> bool {
        self.is_guest
    }
}