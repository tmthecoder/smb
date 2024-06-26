use std::collections::HashMap;
use std::fmt::{Debug, Formatter, Pointer};

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

pub struct SMBLease<S: Server> {
    lease_key: u128,
    client_lease_id: u64,
    file_name: String,
    lease_state: SMBLeaseState,
    break_to_lease_state: SMBLeaseState,
    lease_break_timeout: u64,
    lease_opens: Vec<SMBOpen<S>>,
    breaking: bool,
    held: bool,
    break_notification: SMBLeaseBreakNotification,
    file_delete_on_close: bool,
    epoch: u64,
    parent_lease_key: u128,
    version: u8
}

impl<S: Server> Debug for SMBLease<S> where S::Handle: Debug, S: Debug, S::Session: Debug, S::Share: Debug {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SMBLease")
            .field("lease_key", &self.lease_key)
            .field("client_lease_id", &self.client_lease_id)
            .field("file_name", &self.file_name)
            .field("lease_state", &self.lease_state)
            .field("break_to_lease_state", &self.break_to_lease_state)
            .field("lease_break_timeout", &self.lease_break_timeout)
            .field("lease_opens", &self.lease_opens)
            .field("breaking", &self.breaking)
            .field("break_notification", &self.break_notification)
            .field("file_delete_on_close", &self.file_delete_on_close)
            .field("epoch", &self.epoch)
            .field("parent_lease_key", &self.parent_lease_key)
            .field("epoch", &self.epoch)
            .field("parent_lease_key", &self.parent_lease_key)
            .field("version", &self.version)
            .finish()
    }
}

impl<S: Server> Lease for SMBLease<S> {}

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