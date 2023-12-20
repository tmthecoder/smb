use std::collections::HashMap;

use bitflags::bitflags;
use uuid::Uuid;

use crate::server::open::Open;

pub struct SMBLeaseTable {
    client_guid: Uuid,
    lease_list: HashMap<u64, SMBLease>
}

pub struct SMBLease {
    lease_key: u128,
    client_lease_id: u64,
    file_name: String,
    lease_state: SMBLeaseState,
    break_to_lease_state: SMBLeaseState,
    lease_break_timeout: u64,
    lease_opens: Vec<Box<dyn Open>>,
    breaking: bool,
    held: bool,
    break_notification: SMBLeaseBreakNotification,
    file_delete_on_close: bool,
    epoch: u64,
    parent_lease_key: u128,
    version: u8
}

pub struct SMBLeaseBreakNotification {
    new_epoch: u16,
    flags: SMBLeaseBreakNotificationFlags,
    lease_key: [u8; 16],
    current_lease_state: SMBLeaseState,
    new_lease_state: SMBLeaseState,
}

bitflags! {
    pub struct SMBLeaseState: u8 {
        const READ_CACHING = 0x1;
        const WRITE_CACHING = 0x2;
        const HANDLE_CACHING = 0x4;
    }
}

bitflags! {
    pub struct SMBLeaseBreakNotificationFlags: u32 {
        const NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED = 0x01;
    }
}