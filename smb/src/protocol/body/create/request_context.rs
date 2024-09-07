use std::marker::PhantomData;

use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use smb_core::{SMBByteSize, SMBFromBytes, SMBParseResult, SMBToBytes};
use smb_core::error::SMBError;
use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::context_helper::{create_ctx_smb_byte_size, create_ctx_smb_from_bytes, create_ctx_smb_to_bytes, CreateContextWrapper, impl_tag_for_ctx};
use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::filetime::FileTime;
use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

pub const EA_BUFFER_TAG: &[u8] = "ExtA".as_bytes();
pub const SD_BUFFER_TAG: &[u8] = "SecD".as_bytes();
pub const DURABLE_HANDLE_REQUEST_TAG: &[u8] = "DHnQ".as_bytes();
pub const DURABLE_HANDLE_RECONNECT_TAG: &[u8] = "DHnC".as_bytes();
pub const ALLOCATION_SIZE_TAG: &[u8] = "AlSi".as_bytes();
pub const QUERY_MAXIMAL_ACCESS_REQUEST_TAG: &[u8] = "MxAc".as_bytes();
pub const TIMEWARP_TOKEN_TAG: &[u8] = "TWrp".as_bytes();
pub const QUERY_ON_DISK_ID_TAG: &[u8] = "QFid".as_bytes();
// Same tag for v1 and v2, different by data length
pub const REQUEST_LEASE_TAG: &[u8] = "RqLs".as_bytes();
pub const DURABLE_HANDLE_REQUEST_V2_TAG: &[u8] = "DH2Q".as_bytes();
pub const DURABLE_HANDLE_RECONNECT_V2_TAG: &[u8] = "DH2C".as_bytes();
pub const APP_INSTANCE_ID_TAG: &[u8] = &[
    0x45, 0xBC, 0xA6, 0x6A, 0xEF, 0xA7, 0xF7, 0x4A, 0x90, 0x08, 0xFA, 0x46, 0x2E, 0x14, 0x4D, 0x74
];
pub const APP_INSTANCE_VERSION_TAG: &[u8] = &[
    0xB9, 0x82, 0xD0, 0xB7, 0x3B, 0x56, 0x07, 0x4F, 0xA0, 0x7B, 0x52, 0x4A, 0x81, 0x16, 0xA0, 0x10
];
pub const SVHDX_OPEN_DEVICE_CONTEXT_TAG: &[u8] = &[
    0x9C, 0xCB, 0xCF, 0x9E, 0x04, 0xC1, 0xE6, 0x43, 0x98, 0x0E, 0x15, 0x8D, 0xA1, 0xF6, 0xEC, 0x83
];
pub const RESERVED: &[u8] = &[
    0x93, 0xAD, 0x25, 0x50, 0x9C, 0xB4, 0x11, 0xE7, 0xB4, 0x23, 0x83, 0xDE, 0x96, 0x8B, 0xCD, 0x7C
];

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CreateRequestContext {
    EABuffer(EABuffer),
    SDBuffer(SDBuffer),
    DurableHandleRequest(DurableHandleRequest),
    DurableHandleReconnect(DurableHandleReconnect),
    AllocationSize(AllocationSize),
    QueryMaximalAccessRequest(QueryMaximalAccessRequest),
    TimewarpToken(TimewarpToken),
    QueryOnDiskID(QueryOnDiskID),
    RequestLease(RequestLease),
    RequestLeaseV2(RequestLeaseV2),
    DurableHandleRequestV2(DurableHandleRequestV2),
    DurableHandleReconnectV2(DurableHandleReconnectV2),
    AppInstanceID(AppInstanceID),
    AppInstanceVersion(AppInstanceVersion),
    SVHDXOpenDeviceContext(SVHDXOpenDeviceContext),
}

impl SMBByteSize for CreateRequestContext {
    fn smb_byte_size(&self) -> usize {
        match self {
            CreateRequestContext::EABuffer(x) => create_ctx_smb_byte_size!(x),
            CreateRequestContext::SDBuffer(x) => create_ctx_smb_byte_size!(x),
            CreateRequestContext::DurableHandleRequest(x) => create_ctx_smb_byte_size!(x),
            CreateRequestContext::DurableHandleReconnect(x) => create_ctx_smb_byte_size!(x),
            CreateRequestContext::AllocationSize(x) => create_ctx_smb_byte_size!(x),
            CreateRequestContext::QueryMaximalAccessRequest(x) => create_ctx_smb_byte_size!(x),
            CreateRequestContext::TimewarpToken(x) => create_ctx_smb_byte_size!(x),
            CreateRequestContext::QueryOnDiskID(x) => create_ctx_smb_byte_size!(x),
            CreateRequestContext::RequestLease(x) => create_ctx_smb_byte_size!(x),
            CreateRequestContext::RequestLeaseV2(x) => create_ctx_smb_byte_size!(x),
            CreateRequestContext::DurableHandleRequestV2(x) => create_ctx_smb_byte_size!(x),
            CreateRequestContext::DurableHandleReconnectV2(x) => create_ctx_smb_byte_size!(x),
            CreateRequestContext::AppInstanceID(x) => create_ctx_smb_byte_size!(x),
            CreateRequestContext::AppInstanceVersion(x) => create_ctx_smb_byte_size!(x),
            CreateRequestContext::SVHDXOpenDeviceContext(x) => create_ctx_smb_byte_size!(x),
        }
    }
}

impl SMBFromBytes for CreateRequestContext {
    fn smb_from_bytes(input: &[u8]) -> SMBParseResult<&[u8], Self> where Self: Sized {
        println!("parsing wrapper");
        let (remaining, wrapper) = CreateContextWrapper::smb_from_bytes(input)?;
        println!("got wrapper: {:?}", wrapper);

        let context = match wrapper.name.as_slice() {
            EA_BUFFER_TAG => create_ctx_smb_from_bytes!(
                Self::EABuffer,
                EABuffer::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            SD_BUFFER_TAG => create_ctx_smb_from_bytes!(
                Self::SDBuffer,
                SDBuffer::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            DURABLE_HANDLE_REQUEST_TAG => create_ctx_smb_from_bytes!(
                Self::DurableHandleRequest,
                DurableHandleRequest::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            DURABLE_HANDLE_RECONNECT_TAG => create_ctx_smb_from_bytes!(
                Self::DurableHandleReconnect,
                DurableHandleReconnect::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            ALLOCATION_SIZE_TAG => create_ctx_smb_from_bytes!(
                Self::AllocationSize,
                AllocationSize::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            QUERY_MAXIMAL_ACCESS_REQUEST_TAG if !wrapper.data.is_empty() => create_ctx_smb_from_bytes!(
                Self::QueryMaximalAccessRequest,
                QueryMaximalAccessRequest::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            // TODO investigate -- MacOS seems to send an empty payload here...
            QUERY_MAXIMAL_ACCESS_REQUEST_TAG if wrapper.data.is_empty() => Ok(Self::QueryMaximalAccessRequest(
                QueryMaximalAccessRequest {
                    timestamp: FileTime::zero()
                }
            )),
            TIMEWARP_TOKEN_TAG => create_ctx_smb_from_bytes!(
                Self::TimewarpToken,
                TimewarpToken::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            QUERY_ON_DISK_ID_TAG => create_ctx_smb_from_bytes!(
                Self::QueryOnDiskID,
                QueryOnDiskID::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            REQUEST_LEASE_TAG if wrapper.data.len() == 32 => create_ctx_smb_from_bytes!(
                Self::RequestLease,
                RequestLease::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            REQUEST_LEASE_TAG if wrapper.data.len() == 52 => create_ctx_smb_from_bytes!(
                Self::RequestLeaseV2,
                RequestLeaseV2::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            DURABLE_HANDLE_REQUEST_V2_TAG => create_ctx_smb_from_bytes!(
                Self::DurableHandleRequestV2,
                DurableHandleRequestV2::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            DURABLE_HANDLE_RECONNECT_V2_TAG => create_ctx_smb_from_bytes!(
                Self::DurableHandleReconnectV2,
                DurableHandleReconnectV2::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            APP_INSTANCE_ID_TAG => create_ctx_smb_from_bytes!(
                Self::AppInstanceID,
                AppInstanceID::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            APP_INSTANCE_VERSION_TAG => create_ctx_smb_from_bytes!(
                Self::AppInstanceVersion,
                AppInstanceVersion::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            SVHDX_OPEN_DEVICE_CONTEXT_TAG => create_ctx_smb_from_bytes!(
                Self::SVHDXOpenDeviceContext,
                SVHDXOpenDeviceContext::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            _ => Err(SMBError::parse_error("Invalid context tag"))
        }?;

        Ok((remaining, context))
    }
}

impl SMBToBytes for CreateRequestContext {
    fn smb_to_bytes(&self) -> Vec<u8> {
        match self {
            CreateRequestContext::EABuffer(x) => create_ctx_smb_to_bytes!(x, EA_BUFFER_TAG),
            CreateRequestContext::SDBuffer(x) => create_ctx_smb_to_bytes!(x, SD_BUFFER_TAG),
            CreateRequestContext::DurableHandleRequest(x) => create_ctx_smb_to_bytes!(x, DURABLE_HANDLE_REQUEST_TAG),
            CreateRequestContext::DurableHandleReconnect(x) => create_ctx_smb_to_bytes!(x, DURABLE_HANDLE_RECONNECT_TAG),
            CreateRequestContext::AllocationSize(x) => create_ctx_smb_to_bytes!(x, ALLOCATION_SIZE_TAG),
            CreateRequestContext::QueryMaximalAccessRequest(x) => create_ctx_smb_to_bytes!(x, QUERY_MAXIMAL_ACCESS_REQUEST_TAG),
            CreateRequestContext::TimewarpToken(x) => create_ctx_smb_to_bytes!(x, TIMEWARP_TOKEN_TAG),
            CreateRequestContext::QueryOnDiskID(x) => create_ctx_smb_to_bytes!(x, QUERY_ON_DISK_ID_TAG),
            CreateRequestContext::RequestLease(x) => create_ctx_smb_to_bytes!(x, REQUEST_LEASE_TAG),
            CreateRequestContext::RequestLeaseV2(x) => create_ctx_smb_to_bytes!(x, REQUEST_LEASE_TAG),
            CreateRequestContext::DurableHandleRequestV2(x) => create_ctx_smb_to_bytes!(x, DURABLE_HANDLE_REQUEST_V2_TAG),
            CreateRequestContext::DurableHandleReconnectV2(x) => create_ctx_smb_to_bytes!(x, DURABLE_HANDLE_RECONNECT_V2_TAG),
            CreateRequestContext::AppInstanceID(x) => create_ctx_smb_to_bytes!(x, APP_INSTANCE_ID_TAG),
            CreateRequestContext::AppInstanceVersion(x) => create_ctx_smb_to_bytes!(x, APP_INSTANCE_VERSION_TAG),
            CreateRequestContext::SVHDXOpenDeviceContext(x) => create_ctx_smb_to_bytes!(x, SVHDX_OPEN_DEVICE_CONTEXT_TAG),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct EABuffer {
    #[smb_direct(start(fixed = 4))]
    flags: EABufferFlags,
    #[smb_string(order = 0, length(inner(start = 5, num_type = "u8")), underlying = "u8")]
    name: String,
    #[smb_buffer(order = 1, length(inner(start = 6, num_type = "u16")))]
    value: Vec<u8>,
}

#[repr(u8)]
#[derive(
Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Clone, Ord, PartialOrd, Copy, SMBFromBytes, SMBByteSize, SMBToBytes
)]
pub enum EABufferFlags {
    None = 0x0,
    NeedEA = 0x80,
}

// TODO
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct SDBuffer {
    // revision: u8,
    // sbz1: u8,
    // control: u16,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct DurableHandleRequest {
    #[smb_skip(start = 0, length = 16)]
    reserved_1: PhantomData<Vec<u8>>,
    #[smb_skip(start = 0, length = 16)]
    reserved_2: PhantomData<Vec<u8>>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct DurableHandleReconnect {
    #[smb_direct(start(fixed = 0))]
    file_id: SMBFileId,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct QueryMaximalAccessRequest {
    #[smb_direct(start(fixed = 0))]
    timestamp: FileTime,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct AllocationSize {
    #[smb_direct(start(fixed = 0))]
    size: u64,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct TimewarpToken {
    #[smb_direct(start(fixed = 0))]
    timestamp: FileTime,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct RequestLease {
    #[smb_direct(start(fixed = 0))]
    lease_key: [u8; 16],
    #[smb_direct(start(fixed = 16))]
    lease_state: RequestLeaseState,
    #[smb_skip(start = 20, length = 4)]
    lease_flags: PhantomData<Vec<u8>>,
    #[smb_skip(start = 24, length = 8)]
    lease_duration: PhantomData<Vec<u8>>,
}

bitflags! {
    #[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
    pub struct RequestLeaseState: u32 {
        const NONE = 0;
        const READ_CACHING = 0x1;
        const HANDLE_CACHING = 0x2;
        const WRITE_CACHING = 0x4;
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct QueryOnDiskID {}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct RequestLeaseV2 {
    #[smb_direct(start(fixed = 0))]
    lease_key: [u8; 16],
    #[smb_direct(start(fixed = 16))]
    lease_state: RequestLeaseState,
    #[smb_direct(start(fixed = 20))]
    lease_flags: RequestLeaseFlags,
    #[smb_skip(start = 24, length = 8)]
    lease_duration: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 32))]
    parent_lease_key: [u8; 16],
    #[smb_direct(start(fixed = 48))]
    epoch: u16,
    #[smb_skip(start = 50, length = 2)]
    reserved: PhantomData<Vec<u8>>,
}

bitflags! {
    #[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
    pub struct RequestLeaseFlags: u32 {
        const PARENT_KEY_SET = 0x4;
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct DurableHandleRequestV2 {
    #[smb_direct(start(fixed = 0))]
    timeout: u32,
    #[smb_direct(start(fixed = 4))]
    flags: DurableHandleV2Flags,
    #[smb_skip(start = 8, length = 8)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 16))]
    create_guid: Uuid,
}

bitflags! {
    #[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
    pub struct DurableHandleV2Flags: u32 {
        const PERSISTENT = 0x2;
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct DurableHandleReconnectV2 {
    #[smb_direct(start(fixed = 0))]
    file_id: SMBFileId,
    #[smb_direct(start(fixed = 16))]
    create_guid: Uuid,
    #[smb_direct(start(fixed = 32))]
    flags: DurableHandleV2Flags,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
#[smb_byte_tag(value = 20)]
pub struct AppInstanceID {
    #[smb_skip(start = 0, length = 4)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 4))]
    app_instance_id: [u8; 16],
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
#[smb_byte_tag(20)]
pub struct AppInstanceVersion {
    #[smb_skip(start = 0, length = 4)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_skip(start = 4, length = 4)]
    padding: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 8))]
    app_instance_version_high: u64,
    #[smb_direct(start(fixed = 16))]
    app_instance_version_low: u64,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct SVHDXOpenDeviceContext {}

impl_tag_for_ctx!(EABuffer, EA_BUFFER_TAG);
impl_tag_for_ctx!(SDBuffer, SD_BUFFER_TAG);
impl_tag_for_ctx!(DurableHandleRequest, DURABLE_HANDLE_REQUEST_TAG);
impl_tag_for_ctx!(DurableHandleReconnect, DURABLE_HANDLE_RECONNECT_TAG);
impl_tag_for_ctx!(AllocationSize, ALLOCATION_SIZE_TAG);
impl_tag_for_ctx!(QueryMaximalAccessRequest, QUERY_MAXIMAL_ACCESS_REQUEST_TAG);
impl_tag_for_ctx!(TimewarpToken, TIMEWARP_TOKEN_TAG);
impl_tag_for_ctx!(QueryOnDiskID, QUERY_ON_DISK_ID_TAG);
impl_tag_for_ctx!(RequestLease, REQUEST_LEASE_TAG);
impl_tag_for_ctx!(RequestLeaseV2, REQUEST_LEASE_TAG);
impl_tag_for_ctx!(DurableHandleRequestV2, DURABLE_HANDLE_REQUEST_V2_TAG);
impl_tag_for_ctx!(DurableHandleReconnectV2, DURABLE_HANDLE_RECONNECT_V2_TAG);
impl_tag_for_ctx!(AppInstanceID, APP_INSTANCE_ID_TAG);
impl_tag_for_ctx!(AppInstanceVersion, APP_INSTANCE_VERSION_TAG);
impl_tag_for_ctx!(SVHDXOpenDeviceContext, SVHDX_OPEN_DEVICE_CONTEXT_TAG);

impl_smb_from_bytes_for_bitflag! {RequestLeaseState RequestLeaseFlags DurableHandleV2Flags}
impl_smb_to_bytes_for_bitflag! {RequestLeaseState RequestLeaseFlags DurableHandleV2Flags}
impl_smb_byte_size_for_bitflag! {RequestLeaseState RequestLeaseFlags DurableHandleV2Flags}

