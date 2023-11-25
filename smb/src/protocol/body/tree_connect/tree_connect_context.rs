use std::marker::PhantomData;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use smb_core::SMBFromBytes;
use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

pub enum SMBTreeConnectContext {
    RemotedIdentity(RemotedIdentity),
}

pub struct RemotedIdentity {
    user: SidAttrData,
    user_name: String,
    domain: String,
    groups: SidArrayData,
    restricted_groups: SidArrayData,
    privileges: PrivilegeArrayData,
    primary_group: SidArrayData,
    owner: BlobData,
    default_dacl: BlobData,
    user_claims: BlobData,
    device_claims: BlobData,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct BlobData {
    #[smb_skip(start = 0, length = 2)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_vector(order = 1, count(start = 0, num_type = "u16"))]
    data: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct SidAttrData {
    #[smb_direct(start(fixed = 0))]
    sid_data: BlobData,
    #[smb_direct(start = "current_pos", order = 1)]
    attr: SidAttr,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct SidArrayData {
    #[smb_skip(start = 0, length = 2)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_vector(order = 1, count(start = 0, num_type = "u16"))]
    array: Vec<SidAttrData>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct LuidAttrData {
    #[smb_direct(start(fixed = 0))]
    luid: [u8; 8],
    #[smb_direct(start(fixed = 0))]
    attr: LuidAttr,
}

pub type PrivilegeData = BlobData;

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct PrivilegeArrayData {
    #[smb_skip(start = 0, length = 2)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_vector(order = 1, count(start = 0, num_type = "u16"))]
    array: Vec<PrivilegeData>,
}

bitflags! {
    #[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
    struct SidAttr: u32 {
        const GROUP_ENABLED = 0x4;
        const GROUP_ENABLED_BY_DEFAULT = 0x2;
        const GROUP_IDENTITY = 0x20;
        const GROUP_INTEGRITY_ENABLED = 0x40;
        const GROUP_LOGON_ID = 0xC0000000;
        const GROUP_MANDATORY = 0x01;
        const GROUP_OWNER = 0x08;
        const GROUP_RESOURCE = 0x20000000;
        const GROUP_USE_FOR_DENY_ONLY = 0x10;
    }
}

bitflags! {
    #[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
    struct LuidAttr: u32 {
        const E = 0x1E;
        const D = 0x1F;
    }
}

impl_smb_byte_size_for_bitflag! {LuidAttr SidAttr}
impl_smb_from_bytes_for_bitflag! {LuidAttr SidAttr}
impl_smb_to_bytes_for_bitflag! {LuidAttr SidAttr}