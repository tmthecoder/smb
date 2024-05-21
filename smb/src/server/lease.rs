use std::collections::HashMap;

use bitflags::bitflags;
use uuid::Uuid;

use crate::server::connection::Connection;
use crate::server::open::SMBOpen;
use crate::server::Server;

pub trait Lease: Send + Sync {}

#[derive(Debug)]
pub struct SMBLeaseTable<L: Lease> {
    client_guid: Uuid,
    lease_list: HashMap<u64, L>
}

#[derive(Debug)]
pub struct SMBLease<C: Connection, S: Server> {
    lease_key: u128,
    client_lease_id: u64,
    file_name: String,
    lease_state: SMBLeaseState,
    break_to_lease_state: SMBLeaseState,
    lease_break_timeout: u64,
    lease_opens: Vec<SMBOpen<C, S>>,
    breaking: bool,
    held: bool,
    break_notification: SMBLeaseBreakNotification,
    file_delete_on_close: bool,
    epoch: u64,
    parent_lease_key: u128,
    version: u8
}

impl<C: Connection, S: Server> Lease for SMBLease<C, S> {}

#[derive(Debug)]
pub struct SMBLeaseBreakNotification {
    new_epoch: u16,
    flags: SMBLeaseBreakNotificationFlags,
    lease_key: [u8; 16],
    current_lease_state: SMBLeaseState,
    new_lease_state: SMBLeaseState,
}

bitflags! {
    #[derive(Debug)]
    pub struct SMBLeaseState: u8 {
        const READ_CACHING = 0x1;
        const WRITE_CACHING = 0x2;
        const HANDLE_CACHING = 0x4;
    }
}

bitflags! {
    #[derive(Debug)]
    pub struct SMBLeaseBreakNotificationFlags: u32 {
        const NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED = 0x01;
    }
}