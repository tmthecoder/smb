use std::collections::HashMap;
use bitflags::bitflags;
use uuid::Uuid;
use crate::server::SMBOpen;

pub struct SMBLeaseTable {
    client_guid: Uuid,
    lease_list: HashMap<u64, SMBLease>
}

pub struct SMBLease {
    lease_key: u128,
    clent_lease_id: u64,
    file_name: String,
    lease_state: SMBLeaseState,
    break_to_lease_state: SMBLeaseState,
    lease_break_timeout: u64,
    lease_opens: Vec<SMBOpen>,
    breaking: bool,
    held: bool,
    break_notification: ??, // TODO ??
    file_delete_on_close: bool,
    epoch: u64,
    parent_lease_key: u128,
    version: u8
}

bitflags! {
    pub struct SMBLeaseState: u8 {
        const READ_CACHING = 0x1;
        const WRITE_CACHING = 0x2;
        const HANDLE_CACHING = 0x4;
    }
}