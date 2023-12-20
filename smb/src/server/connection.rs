use std::collections::HashMap;

use uuid::Uuid;

use crate::protocol::body::{Capabilities, FileTime, SMBDialect};
use crate::protocol::body::negotiate::{CompressionAlgorithm, NegotiateSecurityMode, RDMATransformID};
use crate::server::{SMBPreauthSession, SMBRequest, SMBSession};
use crate::server::share::SharedResource;

pub trait Connection {}

pub struct SMBConnection<T: SharedResource> {
    command_sequence_window: Vec<u8>, // TODO
    request_list: HashMap<u64, SMBRequest<T>>,
    client_capabilities: Capabilities,
    negotiate_dialect: SMBDialect, // TODO
    async_command_list: Vec<u8>,
    // TODO
    dialect: SMBDialect,
    should_sign: bool,
    client_name: String,
    max_transact_size: u64,
    max_write_size: u64,
    max_read_size: u64,
    supports_multi_credit: bool,
    transport_name: String,
    session_table: HashMap<u64, SMBSession<T>>,
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