use std::cmp::min;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::sync::Arc;

use derive_builder::Builder;
use hkdf::Hkdf;
use nom::AsBytes;
use sha2::Sha256;
use tokio::sync::RwLock;

use smb_core::error::SMBError;
use smb_core::nt_status::NTStatus;
use smb_core::SMBResult;

use crate::protocol::body::dialect::SMBDialect;
use crate::protocol::body::negotiate::context::EncryptionCipher;
use crate::protocol::body::negotiate::context::EncryptionCipher::AES256CCM;
use crate::protocol::body::session_setup::SMBSessionSetupResponse;
use crate::protocol::body::SMBBody;
use crate::protocol::body::tree_connect::SMBTreeConnectResponse;
use crate::protocol::header::{Header, SMBSyncHeader};
use crate::protocol::header::command_code::SMBCommandCode;
use crate::protocol::message::SMBMessage;
use crate::server::connection::Connection;
use crate::server::open::Open;
use crate::server::Server;
use crate::server::tree_connect::TreeConnect;
use crate::util::auth::{AuthContext, AuthProvider};
use crate::util::auth::spnego::{SPNEGOToken, SPNEGOTokenResponseBody};

type SMBMessageType = SMBMessage<SMBSyncHeader, SMBBody>;

const OUTPUT_SIZE_128: usize = 128;
const OUTPUT_SIZE_256: usize = 256;

pub trait LockedSessionMessageHandler {
    fn handle_message(&self, message: &SMBMessage<SMBSyncHeader, SMBBody>) -> impl Future<Output=SMBResult<SMBMessageType>>;
}

trait LockedInternalSessionMessageHandler {
    fn handle_session_setup(&self, message: &SMBMessage<SMBSyncHeader, SMBBody>) -> impl Future<Output=SMBResult<SMBMessageType>>;
    fn handle_tree_connect(&self, message: &SMBMessage<SMBSyncHeader, SMBBody>) -> impl Future<Output=SMBResult<SMBMessageType>>;
}

pub trait Session<C: Connection, A: AuthProvider>: Send + Sync {
    fn init(id: u64, encrypt_data: bool, preauth_integrity_hash_value: Vec<u8>, conn: Arc<RwLock<C>>, provider: Arc<A>) -> Self;
    fn id(&self) -> u64;
    fn connection(&self) -> Arc<RwLock<C>>;
    fn set_connection(&mut self, connection: Arc<RwLock<C>>);
    fn state(&self) -> SessionState;
    fn anonymous(&self) -> bool;
    fn guest(&self) -> bool;
    fn security_context_mut(&mut self) -> &mut A::Context;
    fn provider(&self) -> &Arc<A>;
    fn encrypt_data(&self) -> bool;
    fn handle_message(locked: Arc<RwLock<Self>>, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBMessageType>>;
}

#[derive(Builder)]
#[builder(pattern = "owned")]
pub struct SMBSession<C: Connection, S: Server> {
    session_id: u64,
    state: SessionState,
    security_context: <S::AuthType as AuthProvider>::Context,
    provider: Arc<S::AuthType>,
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

impl<C: Connection, S: Server> SMBSession<C, S> {
    fn set_session_key(&mut self) {
        // Set session_key to first 16 bytes of full key (or right padded if full key is less)
        for num in 0..(min(16, self.full_session_key.len())) {
            self.session_key[num] = self.full_session_key[num];
        }
    }
    fn generate_keys(&mut self, dialect: SMBDialect, cipher_id: EncryptionCipher) {
        let key_length = match cipher_id {
            EncryptionCipher::AES256GCM | AES256CCM => 32,
            _ => 16
        };

        let (signing_key_label, signing_key_context): (&str, &[u8]) = match dialect {
            SMBDialect::V3_1_1 => ("SMBSigningKey", &self.preauth_integrity_hash_value),
            _ => ("SMB2AESCMAC", "SmbSign".as_bytes()),
        };
        self.signing_key = generate_key(&self.session_key, signing_key_label, signing_key_context, key_length);

        let (application_key_label, application_key_context): (&str, &[u8]) = match dialect {
            SMBDialect::V3_1_1 => ("SMBAppKey", &self.preauth_integrity_hash_value),
            _ => ("SMB2APP", "SmbRpc".as_bytes())
        };
        self.application_key = generate_key(&self.session_key, application_key_label, application_key_context, key_length);
    }
}

fn generate_key(secure_key: &[u8], label: &str, context: &[u8], output_len: usize) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::from_prk(secure_key).expect("Session PRK should be good");
    let info_arr = [
        label.as_bytes(),
        &[0x0; 2][..],
        context,
        &[0x0]
    ].concat();
    let mut output_arr = vec![0; output_len];
    hkdf.expand(&info_arr, &mut output_arr).expect("Shouldn't fail");
    output_arr.to_vec()
}

impl<C: Connection, S: Server<SessionType=SMBSession<C, S>>> LockedInternalSessionMessageHandler for Arc<RwLock<SMBSession<C, S>>> {
    async fn handle_session_setup(&self, message: &SMBMessage<SMBSyncHeader, SMBBody>) -> SMBResult<SMBMessageType> {
        if let SMBBody::SessionSetupRequest(request) = &message.body {
            let buffer = request.buffer();
            let (_, token) = SPNEGOToken::<S::AuthType>::parse(buffer)?;
            let mut session_write = self.write().await;
            let provider = session_write.provider.clone();
            let ctx = session_write.security_context_mut();
            let (status, msg) = token.get_message(provider.as_ref(), ctx)?;
            if status == NTStatus::StatusSuccess {
                let session_key = ctx.session_key().to_vec();
                session_write.state = SessionState::Valid;
                session_write.full_session_key = session_key;
            }
            drop(session_write);
            let response = SPNEGOTokenResponseBody::<S::AuthType>::new(status.clone(), msg);
            let (id, session_setup) = {
                let session_read = self.read().await;
                let resp = SMBSessionSetupResponse::from_session_state::<S>(&session_read, response.as_bytes());
                (session_read.id(), resp)
            };
            let header = message.header.create_response_header(status as u32, id);
            Ok(SMBMessage::new(header, SMBBody::SessionSetupResponse(session_setup)))
        } else {
            Err(SMBError::parse_error("Invalid SMB request body (expected SessionSetupRequest)"))
        }
    }

    async fn handle_tree_connect(&self, message: &SMBMessage<SMBSyncHeader, SMBBody>) -> SMBResult<SMBMessageType> {
        println!("{:?}", message);
        if let SMBBody::TreeConnectRequest(req) = &message.body {
            println!("Share: {:?}", req.share());
            let self_rd = self.read().await;
            let conn_rd = self_rd.connection.read().await;
            let server_ref = conn_rd.server_ref().upgrade();
            if server_ref.is_none() {
                return Err(SMBError::response_error(NTStatus::BadNetworkName))
            }
            let server_ref = server_ref.unwrap();
            let server_rd = server_ref.read().await;
            let share = server_rd.shares().get(&req.share().to_lowercase());
            if share.is_none() {
                return Err(SMBError::response_error(NTStatus::BadNetworkName))
            }
            let response = SMBTreeConnectResponse::for_share(share.unwrap());
            let header = SMBSyncHeader::create_response_header(&message.header, 0, self_rd.id());
            ;
            Ok(SMBMessage::new(header, SMBBody::TreeConnectResponse(response)))
        } else {
            Err(SMBError::parse_error("Invalid SMB request body (expected TreeConnectRequest)"))
        }
    }
}

impl<C: Connection, S: Server> SMBSession<C, S> {}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum SessionState {
    InProgress,
    Valid,
    Expired
}

impl<C: Connection, S: Server<SessionType=Self>> Session<C, S::AuthType> for SMBSession<C, S> {
    fn init(id: u64, encrypt_data: bool, preauth_integrity_hash_value: Vec<u8>, conn: Arc<RwLock<C>>, provider: Arc<S::AuthType>) -> Self {
        Self {
            session_id: id,
            state: SessionState::InProgress,
            security_context: <S::AuthType as AuthProvider>::Context::init(),
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

    fn connection(&self) -> Arc<RwLock<C>> {
        self.connection.clone()
    }

    fn set_connection(&mut self, connection: Arc<RwLock<C>>) {
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

    fn security_context_mut(&mut self) -> &mut <S::AuthType as AuthProvider>::Context {
        &mut self.security_context
    }

    fn provider(&self) -> &Arc<S::AuthType> {
        &self.provider
    }

    fn encrypt_data(&self) -> bool {
        self.encrypt_data
    }

    async fn handle_message(locked: Arc<RwLock<Self>>, message: &SMBMessageType) -> SMBResult<SMBMessageType> {
        match message.header.command_code() {
            SMBCommandCode::SessionSetup => locked.handle_session_setup(message).await,
            SMBCommandCode::TreeConnect => locked.handle_tree_connect(message).await,
            _ => Err(SMBError::parse_error("Invalid command code"))
        }
    }
}