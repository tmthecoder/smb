use std::fmt::{Debug, Pointer};

use uuid::Uuid;

use crate::protocol::body::create::oplock::SMBOplockLevel;
use crate::protocol::body::create::options::SMBCreateOptions;
use crate::protocol::body::tree_connect::access_mask::{SMBAccessMask, SMBDirectoryAccessMask};
use crate::server::connection::Connection;
use crate::server::lease::SMBLease;
use crate::server::Server;
use crate::server::session::SMBSession;
use crate::server::share::ResourceHandle;
use crate::server::tree_connect::SMBTreeConnect;

pub trait Open: Send + Sync {
    fn file_name(&self) -> &str;
    fn init(underlying: Box<dyn ResourceHandle>) -> Self;
    fn set_session_id(&mut self, session_id: u32);
    fn set_global_id(&mut self, global_id: u32);
}

#[derive(Debug)]
pub struct SMBOpen<S: Server, H: ResourceHandle> {
    file_share_id: u32,
    session_id: u32,
    global_id: u32,
    session: Option<SMBSession<S>>,
    tree_connect: Option<SMBTreeConnect<S>>,
    connection: Option<S::Connection>,
    granted_access: SMBAccessMask,
    oplock_level: SMBOplockLevel,
    oplock_state: SMBOplockState,
    oplock_timeout: u64,
    is_durable: bool,
    durable_open_timeout: u64,
    durable_open_scavenger_timeout: u64,
    durable_owner: u64,
    underlying: H,
    current_ea_index: u32,
    current_quota_index: u32,
    lock_count: u32,
    path_name: String,
    resume_key: u32,
    file_name: String,
    create_options: SMBCreateOptions,
    file_attributes: FileAttributes,
    client_guid: Uuid,
    lease: Option<SMBLease<S>>,
    is_resilient: bool,
    resiliency_timeout: u32,
    resilient_open_timeout: u32,
    lock_sequence_array: Vec<LockSequence>,
    create_guid: u128,
    app_instance_id: u128,
    is_persistent: bool,
    channel_sequence: u128,
    outstanding_request_count: u32,
    outstanding_pre_request_count: u32,
    is_shared_vhdx: bool,
    application_instance_version_high: u64,
    application_instance_version_low: u64,
}
//
// impl<S: Server + Debug> Debug for SMBOpen<S> {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         f.fmt()
//     }
// }

impl<S: Server, H: ResourceHandle> Open for SMBOpen<S, H> {
    fn file_name(&self) -> &str {
        &self.file_name
    }

    fn init(underlying: Box<dyn ResourceHandle>) -> Self {
        Self {
            file_share_id: 0,
            session_id: 0,
            global_id: 0,
            session: None,
            tree_connect: None,
            connection: None,
            granted_access: SMBAccessMask::Directory(SMBDirectoryAccessMask::GENERIC_ALL),
            oplock_level: SMBOplockLevel::None,
            oplock_state: SMBOplockState::Held,
            oplock_timeout: 0,
            is_durable: false,
            durable_open_timeout: 0,
            durable_open_scavenger_timeout: 0,
            durable_owner: 0,
            underlying,
            current_ea_index: 0,
            current_quota_index: 0,
            lock_count: 0,
            path_name: "".to_string(),
            resume_key: 0,
            file_name: "".to_string(),
            create_options: SMBCreateOptions::all(),
            file_attributes: FileAttributes,
            client_guid: Default::default(),
            lease: None,
            is_resilient: false,
            resiliency_timeout: 0,
            resilient_open_timeout: 0,
            lock_sequence_array: vec![],
            create_guid: 0,
            app_instance_id: 0,
            is_persistent: false,
            channel_sequence: 0,
            outstanding_request_count: 0,
            outstanding_pre_request_count: 0,
            is_shared_vhdx: false,
            application_instance_version_high: 0,
            application_instance_version_low: 0,
        }
    }

    fn set_session_id(&mut self, session_id: u32) {
        self.session_id = session_id;
    }

    fn set_global_id(&mut self, global_id: u32) {
        self.global_id = global_id;
    }
}
// TODO: From MS-FSCC section 2.6
#[derive(Debug)]
struct FileAttributes;

#[derive(Debug)]
pub enum SMBOplockState {
    Held,
    Breaking,
    None
}

#[derive(Debug)]
pub struct LockSequence {
    sequence_number: u32,
    valid: bool,
}