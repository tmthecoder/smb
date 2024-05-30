use std::fmt::{Debug, Formatter, Pointer};

use uuid::Uuid;

use crate::protocol::body::create::oplock::SMBOplockLevel;
use crate::protocol::body::create::options::SMBCreateOptions;
use crate::protocol::body::tree_connect::access_mask::{SMBAccessMask, SMBDirectoryAccessMask};
use crate::server::lease::SMBLease;
use crate::server::Server;
use crate::server::tree_connect::SMBTreeConnect;

pub trait Open: Send + Sync {
    type Server: Server;
    fn file_name(&self) -> &str;
    fn init(underlying: <Self::Server as Server>::Handle) -> Self;
    fn set_session_id(&mut self, session_id: u32);
    fn set_global_id(&mut self, global_id: u32);
}

pub struct SMBOpen<S: Server> {
    file_share_id: u32,
    session_id: u32,
    global_id: u32,
    session: Option<S::Session>,
    tree_connect: Option<SMBTreeConnect<S>>,
    granted_access: SMBAccessMask,
    oplock_level: SMBOplockLevel,
    oplock_state: SMBOplockState,
    oplock_timeout: u64,
    is_durable: bool,
    durable_open_timeout: u64,
    durable_open_scavenger_timeout: u64,
    durable_owner: u64,
    underlying: S::Handle,
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

impl<S: Server> Open for SMBOpen<S> {
    type Server = S;
    fn file_name(&self) -> &str {
        &self.file_name
    }

    fn init(underlying: S::Handle) -> Self {
        Self {
            file_share_id: 0,
            session_id: 0,
            global_id: 0,
            session: None,
            tree_connect: None,
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

impl<S: Server> Debug for SMBOpen<S> where S: Debug, S::Session: Debug, S::Handle: Debug, S::Share: Debug {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SMBOpen")
            .field("file_share_id", &self.file_share_id)
            .field("session_id", &self.session_id)
            .field("global_id", &self.global_id)
            .field("session", &self.session)
            .field("tree_connect", &self.tree_connect)
            .field("granted_access", &self.granted_access)
            .field("oplock_level", &self.oplock_level)
            .field("oplock_state", &self.oplock_state)
            .field("oplock_timeout", &self.oplock_timeout)
            .field("is_durable", &self.is_durable)
            .field("durable_open_timeout", &self.durable_open_timeout)
            .field("durable_open_scavenger_timeout", &self.durable_open_scavenger_timeout)
            .field("durable_owner", &self.durable_owner)
            .field("underlying", &self.underlying)
            .field("current_ea_index", &self.current_ea_index)
            .field("current_quota_index", &self.current_quota_index)
            .field("lock_count", &self.lock_count)
            .field("path_name", &self.path_name)
            .field("resume_key", &self.resume_key)
            .field("file_name", &self.file_name)
            .field("create_options", &self.create_options)
            .field("file_attributes", &self.file_attributes)
            .field("client_guid", &self.client_guid)
            .field("lease", &self.lease)
            .field("is_resilient", &self.is_resilient)
            .field("resiliency_timeout", &self.resiliency_timeout)
            .field("resilient_open_timeout", &self.resilient_open_timeout)
            .field("lock_sequence_array", &self.lock_sequence_array)
            .field("create_guid", &self.create_guid)
            .field("app_instance_id", &self.app_instance_id)
            .field("is_persistent", &self.is_persistent)
            .field("channel_sequence", &self.channel_sequence)
            .field("outstanding_request_count", &self.outstanding_request_count)
            .field("outstanding_pre_request_count", &self.outstanding_pre_request_count)
            .field("is_shared_vhdx", &self.is_shared_vhdx)
            .field("application_instance_version_high", &self.application_instance_version_high)
            .field("application_instance_version_low", &self.application_instance_version_low)
            .finish()
    }
}
