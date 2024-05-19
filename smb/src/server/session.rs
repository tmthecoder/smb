use std::cmp::min;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::io::Read;
use std::ops::Deref;
use std::sync::{Arc, Weak};

use derive_builder::Builder;
use digest::Mac;
use hmac::Hmac;
use nom::AsBytes;
use sha2::Sha256;
use tokio::sync::RwLock;

use smb_core::error::SMBError;
use smb_core::nt_status::NTStatus;
use smb_core::SMBResult;

use crate::protocol::body::dialect::SMBDialect;
use crate::protocol::body::negotiate::context::EncryptionCipher;
use crate::protocol::body::negotiate::context::EncryptionCipher::AES256CCM;
use crate::protocol::body::session_setup::{SMBSessionSetupRequest, SMBSessionSetupResponse};
use crate::protocol::body::SMBBody;
use crate::protocol::body::tree_connect::{SMBTreeConnectRequest, SMBTreeConnectResponse};
use crate::protocol::header::{Header, SMBSyncHeader};
use crate::protocol::message::{Message, SMBMessage};
use crate::server::connection::Connection;
use crate::server::message_handler::{NonEndingHandler, SMBHandlerState, SMBLockedMessageHandlerBase};
use crate::server::open::Open;
use crate::server::Server;
use crate::server::tree_connect::SMBTreeConnect;
use crate::util::auth::{AuthContext, AuthProvider};
use crate::util::auth::spnego::{SPNEGOToken, SPNEGOTokenResponseBody};
use crate::util::crypto::sp800_108::derive_key;

type SMBMessageType = SMBMessage<SMBSyncHeader, SMBBody>;

const OUTPUT_SIZE_128: usize = 128;
const OUTPUT_SIZE_256: usize = 256;


pub trait Session<C: Connection, A: AuthProvider>: Send + Sync {
    fn init(id: u64, encrypt_data: bool, preauth_integrity_hash_value: Vec<u8>, conn: Weak<RwLock<C>>, provider: Arc<A>) -> Self;
    fn id(&self) -> u64;
    fn connection(&self) -> Weak<RwLock<C>>;
    fn connection_res(&self) -> SMBResult<Arc<RwLock<C>>>;
    fn set_connection(&mut self, connection: Weak<RwLock<C>>);
    fn state(&self) -> SessionState;
    fn anonymous(&self) -> bool;
    fn guest(&self) -> bool;
    fn security_context_mut(&mut self) -> &mut A::Context;
    fn provider(&self) -> &Arc<A>;
    fn encrypt_data(&self) -> bool;
}

#[derive(Builder)]
#[builder(pattern = "owned")]
pub struct SMBSession<C: Connection, S: Server> {
    session_id: u64,
    state: SessionState,
    security_context: <S::AuthProvider as AuthProvider>::Context,
    provider: Arc<S::AuthProvider>,
    // TODO >>
    is_anonymous: bool,
    is_guest: bool,
    session_key: [u8; 16],
    signing_required: bool,
    open_table: HashMap<u64, Box<dyn Open>>,
    tree_connect_table: HashMap<u32, Arc<SMBTreeConnect<C, S>>>,
    expiration_time: u64,
    connection: Weak<RwLock<C>>,
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

impl<C: Connection, S: Server> SMBSession<C, S> {
    fn get_connection(&self) -> SMBResult<Arc<RwLock<C>>> {
        self.connection.upgrade()
            .ok_or(SMBError::server_error("Connection not found for session"))
    }
    async fn handle_successful_setup(&mut self, session_key: Vec<u8>) -> SMBResult<()> {
        self.state = SessionState::Valid;
        self.full_session_key = session_key;
        let conn = self.get_connection()?;
        let conn_rd = conn.read().await;
        let dialect = conn_rd.dialect();
        let cipher = conn_rd.cipher_id();
        drop(conn_rd);
        self.set_session_key();
        self.generate_keys(dialect, cipher);
        Ok(())
    }
    fn set_session_key(&mut self) {
        // Set session_key to first 16 bytes of full key (or right padded if full key is less)
        for num in 0..(min(16, self.full_session_key.len())) {
            self.session_key[num] = self.full_session_key[num];
        }
    }
    fn generate_keys(&mut self, dialect: SMBDialect, cipher_id: EncryptionCipher) {
        println!("in keygen");
        let key_length = match cipher_id {
            EncryptionCipher::AES256GCM | AES256CCM => 32,
            _ => 16
        };

        let signing_key_len = 16;

        let smb_sign_bytes = [
            "SmbSign".as_bytes(),
            &[0],
        ].concat();

        let (signing_key_label, signing_key_context): (&str, &[u8]) = match dialect {
            SMBDialect::V3_1_1 => ("SMBSigningKey", &self.preauth_integrity_hash_value),
            _ => ("SMB2AESCMAC", &smb_sign_bytes),
        };
        self.signing_key = match dialect {
            SMBDialect::V3_0_0 | SMBDialect::V3_1_1 => generate_key(&self.session_key, signing_key_label, signing_key_context, signing_key_len),
            _ => self.session_key.clone().to_vec(),
        };

        println!("skey: {:02x?}, signing key: {:02x?}", self.session_key, self.signing_key);

        let (application_key_label, application_key_context): (&str, &[u8]) = match dialect {
            SMBDialect::V3_1_1 => ("SMBAppKey", &self.preauth_integrity_hash_value),
            _ => ("SMB2APP", "SmbRpc".as_bytes())
        };
        self.application_key = generate_key(&self.session_key, application_key_label, application_key_context, key_length);
        println!("signing: {:?}, application: {:?}", self.signing_key, self.application_key);
    }
    fn get_next_tree_id(&self) -> u32 {
        for i in 1..u32::MAX {
            if self.tree_connect_table.get(&i).is_none() {
                return i;
            }
        }
        0
    }
}

fn generate_key(secure_key: &[u8], label: &str, context: &[u8], output_len: usize) -> Vec<u8> {
    println!("key len: {:?}, label: {:02x?}, ctx: {:02x?}", secure_key.len(), label, context);
    let mac = <Hmac<Sha256>>::new_from_slice(secure_key)
        .map_err(|_| SMBError::crypto_error("Invalid Key Length")).unwrap();
    let label_bytes = [
        label.as_bytes(),
        &[0]
    ].concat();
    derive_key(mac, &label_bytes, context, (output_len * 8) as u32)
}

impl<C: Connection<Server=S>, S: Server<Session=SMBSession<C, S>>> NonEndingHandler for Arc<RwLock<SMBSession<C, S>>> {}

impl<C: Connection<Server=S>, S: Server<Session=SMBSession<C, S>>> SMBLockedMessageHandlerBase for Arc<RwLock<SMBSession<C, S>>> {
    type Inner = Arc<SMBTreeConnect<C, S>>;
    async fn inner(&self, message: &SMBMessageType) -> Option<Self::Inner> {
        let write = self.write().await;
        println!("Getting tree connect for message: {:?}", message);
        write.tree_connect_table.get(&message.header.tree_id)
            .map(Arc::clone)
    }

    async fn handle_session_setup(&mut self, header: &SMBSyncHeader, request: &SMBSessionSetupRequest) -> SMBResult<SMBHandlerState<Self::Inner>> {
        let buffer = request.buffer();
        let (_, token) = SPNEGOToken::<S::AuthProvider>::parse(buffer)?;
        let mut session_write = self.write().await;
        let provider = session_write.provider.clone();
        let ctx = session_write.security_context_mut();
        let (status, msg) = token.get_message(provider.as_ref(), ctx)?;
        if status == NTStatus::StatusSuccess {
            let session_key = ctx.session_key().to_vec();
            session_write.handle_successful_setup(session_key).await?;
            println!("session key: {:02x?}", session_write.session_key);
        }
        drop(session_write);
        let response = SPNEGOTokenResponseBody::<S::AuthProvider>::new(status, msg);
        let (id, session_setup) = {
            let session_read = self.read().await;
            let resp = SMBSessionSetupResponse::from_session_state::<S>(&session_read, response.as_bytes());
            (session_read.id(), resp)
        };
        let header = header.create_response_header(status as u32, id, 0);
        let message = SMBMessage::new(header, SMBBody::SessionSetupResponse(session_setup));
        Ok(SMBHandlerState::Finished(message))
    }

    async fn handle_tree_connect(&mut self, header: &SMBSyncHeader, request: &SMBTreeConnectRequest) -> SMBResult<SMBHandlerState<Self::Inner>> {
        let self_rd = self.read().await;
        let conn = self_rd.get_connection()?;
        drop(self_rd);
        let conn_rd = conn.read().await;
        let self_rd = self.read().await;
        let server_ref = conn_rd.server_ref().upgrade();
        if server_ref.is_none() {
            return Err(SMBError::response_error(NTStatus::BadNetworkName))
        }
        let server_ref = server_ref.unwrap();
        let server_rd = server_ref.read().await;
        let share = server_rd.shares().get(&request.share().to_lowercase());
        if share.is_none() {
            return Err(SMBError::response_error(NTStatus::BadNetworkName))
        }
        let share = share.unwrap();
        let response = SMBTreeConnectResponse::for_share(share.deref());
        let tree_id = self_rd.get_next_tree_id();
        let tree_connect = SMBTreeConnect::init(tree_id, Arc::downgrade(self), share.clone(), response.access_mask().clone());
        let header = SMBSyncHeader::create_response_header(&header, 0, self_rd.id(), 1);
        drop(self_rd);
        let mut self_wr = self.write().await;
        self_wr.tree_connect_table.insert(tree_id, Arc::new(tree_connect));
        let message = SMBMessage::new(header, SMBBody::TreeConnectResponse(response));
        Ok(SMBHandlerState::Finished(message))
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum SessionState {
    InProgress,
    Valid,
    Expired
}

impl<C: Connection, S: Server<Session=Self>> Session<C, S::AuthProvider> for SMBSession<C, S> {
    fn init(id: u64, encrypt_data: bool, preauth_integrity_hash_value: Vec<u8>, conn: Weak<RwLock<C>>, provider: Arc<S::AuthProvider>) -> Self {

        Self {
            session_id: id,
            state: SessionState::InProgress,
            security_context: <S::AuthProvider as AuthProvider>::Context::init(),
            provider,
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

    fn connection(&self) -> Weak<RwLock<C>> {
        self.connection.clone()
    }

    fn connection_res(&self) -> SMBResult<Arc<RwLock<C>>> {
        self.connection.upgrade()
            .ok_or(SMBError::server_error("Connection not found for session"))
    }

    fn set_connection(&mut self, connection: Weak<RwLock<C>>) {
        self.connection = connection;
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

    fn security_context_mut(&mut self) -> &mut <S::AuthProvider as AuthProvider>::Context {
        &mut self.security_context
    }

    fn provider(&self) -> &Arc<S::AuthProvider> {
        &self.provider
    }

    fn encrypt_data(&self) -> bool {
        self.encrypt_data
    }
}