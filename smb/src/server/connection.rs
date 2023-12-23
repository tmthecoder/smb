use std::collections::HashMap;
use std::fmt::Debug;

use uuid::Uuid;

use smb_core::error::SMBError;

use crate::protocol::body::{Capabilities, FileTime, SMBDialect};
use crate::protocol::body::negotiate::{CompressionAlgorithm, NegotiateSecurityMode, RDMATransformID};
use crate::server::SMBPreauthSession;
use crate::server::request::Request;
use crate::server::session::Session;
use crate::SMBMessageStream;

pub trait Connection: Debug {}

#[derive(Debug)]
pub struct SMBConnection {
    command_sequence_window: Vec<u32>,
    request_list: HashMap<u64, Box<dyn Request>>,
    client_capabilities: Capabilities,
    negotiate_dialect: SMBDialect,
    async_command_list: HashMap<u64, Box<dyn Request>>,
    dialect: SMBDialect,
    should_sign: bool,
    client_name: String,
    max_transact_size: u64,
    max_write_size: u64,
    max_read_size: u64,
    supports_multi_credit: bool,
    transport_name: String,
    session_table: HashMap<u64, Box<dyn Session>>,
    creation_time: FileTime,
    preauth_session_table: HashMap<u64, SMBPreauthSession>, // TODO
    clint_guid: Uuid,
    server_capabilites: Capabilities,
    client_security_mode: NegotiateSecurityMode,
    server_security_mode: NegotiateSecurityMode,
    constrained_connection: bool,
    preauth_integrity_hash_id: u64, // TODO
    preauth_integrity_hash_value: Vec<u8>, // TODO
    cipher_id: u64,
    client_dialects: Vec<SMBDialect>,
    compression_ids: Vec<CompressionAlgorithm>, // TODO ??
    supports_chained_compression: bool,
    rdma_transform_ids: Vec<RDMATransformID>, // TODO ??
    signing_algorithm_id: u64,
    accept_transport_security: bool,
}

impl TryFrom<SMBMessageStream> for SMBConnection {
    type Error = SMBError;

    fn try_from(value: SMBMessageStream) -> Result<Self, Self::Error> {
        todo!()
    }
}