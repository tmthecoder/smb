use std::marker::PhantomData;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use smb_core::{SMBByteSize, SMBFromBytes, SMBParseResult, SMBToBytes};
use smb_core::error::SMBError;
use smb_core::nt_status::NTStatus;
use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::context_helper::{create_ctx_smb_byte_size, create_ctx_smb_from_bytes, create_ctx_smb_to_bytes, CreateContextWrapper, impl_tag_for_ctx};
use crate::protocol::body::create::request_context::{DURABLE_HANDLE_REQUEST_TAG, DURABLE_HANDLE_REQUEST_V2_TAG, DurableHandleV2Flags, QUERY_MAXIMAL_ACCESS_REQUEST_TAG, QUERY_ON_DISK_ID_TAG, REQUEST_LEASE_TAG, RequestLeaseState, SVHDX_OPEN_DEVICE_CONTEXT_TAG};
use crate::protocol::body::tree_connect::access_mask::SMBFilePipePrinterAccessMask;
use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

const DURABLE_HANDLE_RESPONSE_TAG: &[u8] = DURABLE_HANDLE_REQUEST_TAG;
const QUERY_MAXIMAL_ACCESS_RESPONSE_TAG: &[u8] = QUERY_MAXIMAL_ACCESS_REQUEST_TAG;
const QUERY_ON_DISK_ID_RESPONSE_TAG: &[u8] = QUERY_ON_DISK_ID_TAG;

// Same for v1 and v2
const RESPONSE_LEASE_TAG: &[u8] = REQUEST_LEASE_TAG;
const DURABLE_HANDLE_RESPONSE_V2_TAG: &[u8] = DURABLE_HANDLE_REQUEST_V2_TAG;
const SVHDX_OPEN_DEVICE_CONTEXT_RESPONSE_TAG: &[u8] = SVHDX_OPEN_DEVICE_CONTEXT_TAG;

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CreateResponseContext {
    DurableHandleResponse(DurableHandleResponse),
    QueryMaximalAccessResponse(QueryMaximalAccessResponse),
    QueryOnDiskIDResponse(QueryOnDiskIDResponse),
    ResponseLease(ResponseLease),
    ResponseLeaseV2(ResponseLeaseV2),
    DurableHandleResponseV2(DurableHandleResponseV2),
    SVHDXOpenDeviceContext(SVHDXOpenDeviceContext),
}

impl SMBByteSize for CreateResponseContext {
    fn smb_byte_size(&self) -> usize {
        match self {
            CreateResponseContext::DurableHandleResponse(x) => create_ctx_smb_byte_size!(x),
            CreateResponseContext::QueryMaximalAccessResponse(x) => create_ctx_smb_byte_size!(x),
            CreateResponseContext::QueryOnDiskIDResponse(x) => create_ctx_smb_byte_size!(x),
            CreateResponseContext::ResponseLease(x) => create_ctx_smb_byte_size!(x),
            CreateResponseContext::ResponseLeaseV2(x) => create_ctx_smb_byte_size!(x),
            CreateResponseContext::DurableHandleResponseV2(x) => create_ctx_smb_byte_size!(x),
            CreateResponseContext::SVHDXOpenDeviceContext(x) => create_ctx_smb_byte_size!(x),
        }
    }
}

impl SMBFromBytes for CreateResponseContext {
    fn smb_from_bytes(input: &[u8]) -> SMBParseResult<&[u8], Self> where Self: Sized {
        println!("parsing wrapper");
        let (remaining, wrapper) = CreateContextWrapper::smb_from_bytes(input)?;

        println!("got ctx wrapper: {:02x?}", wrapper);
        let context = match wrapper.name.as_slice() {
            DURABLE_HANDLE_RESPONSE_TAG => create_ctx_smb_from_bytes!(
                Self::DurableHandleResponse,
                DurableHandleResponse::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            QUERY_MAXIMAL_ACCESS_RESPONSE_TAG => create_ctx_smb_from_bytes!(
                Self::QueryMaximalAccessResponse,
                QueryMaximalAccessResponse::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            QUERY_ON_DISK_ID_RESPONSE_TAG => create_ctx_smb_from_bytes!(
                Self::QueryOnDiskIDResponse,
                QueryOnDiskIDResponse::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            RESPONSE_LEASE_TAG if wrapper.data.len() == 32 => create_ctx_smb_from_bytes!(
                Self::ResponseLease,
                ResponseLease::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            RESPONSE_LEASE_TAG if wrapper.data.len() == 52 => create_ctx_smb_from_bytes!(
                Self::ResponseLeaseV2,
                ResponseLeaseV2::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            DURABLE_HANDLE_RESPONSE_V2_TAG => create_ctx_smb_from_bytes!(
                Self::DurableHandleResponseV2,
                DurableHandleResponseV2::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            SVHDX_OPEN_DEVICE_CONTEXT_RESPONSE_TAG => create_ctx_smb_from_bytes!(
                Self::SVHDXOpenDeviceContext,
                SVHDXOpenDeviceContext::smb_from_bytes,
                wrapper.data.as_slice()
            ),
            _ => Err(SMBError::parse_error("Invalid context tag"))
        }?;

        Ok((remaining, context))
    }
}

impl SMBToBytes for CreateResponseContext {
    fn smb_to_bytes(&self) -> Vec<u8> {
        match self {
            CreateResponseContext::DurableHandleResponse(x) => create_ctx_smb_to_bytes!(x, DURABLE_HANDLE_REQUEST_TAG),
            CreateResponseContext::QueryMaximalAccessResponse(x) => create_ctx_smb_to_bytes!(x, QUERY_MAXIMAL_ACCESS_REQUEST_TAG),
            CreateResponseContext::QueryOnDiskIDResponse(x) => create_ctx_smb_to_bytes!(x, QUERY_ON_DISK_ID_RESPONSE_TAG),
            CreateResponseContext::ResponseLease(x) => create_ctx_smb_to_bytes!(x, REQUEST_LEASE_TAG),
            CreateResponseContext::ResponseLeaseV2(x) => create_ctx_smb_to_bytes!(x, REQUEST_LEASE_TAG),
            CreateResponseContext::DurableHandleResponseV2(x) => create_ctx_smb_to_bytes!(x, DURABLE_HANDLE_REQUEST_V2_TAG),
            CreateResponseContext::SVHDXOpenDeviceContext(x) => create_ctx_smb_to_bytes!(x, SVHDX_OPEN_DEVICE_CONTEXT_TAG),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct DurableHandleResponse {
    #[smb_skip(start = 0, length = 8)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_skip(start = 0, length = 8)]
    reserved2: PhantomData<Vec<u8>>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct QueryMaximalAccessResponse {
    #[smb_direct(start(fixed = 0))]
    status: NTStatus,
    #[smb_direct(start(fixed = 4))]
    maximal_access: SMBFilePipePrinterAccessMask,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct QueryOnDiskIDResponse {
    #[smb_direct(start(fixed = 0))]
    disk_file_id: u64,
    #[smb_direct(start(fixed = 8))]
    volume_id: u64,
    #[smb_skip(start = 16, length = 16)]
    reserved: PhantomData<Vec<u8>>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct ResponseLease {
    #[smb_direct(start(fixed = 0))]
    lease_key: [u8; 16],
    #[smb_direct(start(fixed = 16))]
    lease_state: ResponseLeaseState,
    #[smb_direct(start(fixed = 20))]
    lease_flags: ResponseLeaseFlags,
    #[smb_skip(start = 24, length = 8)]
    lease_duration: PhantomData<Vec<u8>>,
}

pub type ResponseLeaseState = RequestLeaseState;

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct ResponseLeaseV2 {
    #[smb_direct(start(fixed = 0))]
    lease_key: [u8; 16],
    #[smb_direct(start(fixed = 16))]
    lease_state: ResponseLeaseState,
    #[smb_direct(start(fixed = 20))]
    lease_flags: ResponseLeaseFlags,
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
    pub struct ResponseLeaseFlags: u32 {
        const BREAK_IN_PROGRESS = 0x2;
        const PARENT_LEASE_KEY_SET = 0x4;
    }
}
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct DurableHandleResponseV2 {
    #[smb_direct(start(fixed = 0))]
    timeout: u32,
    #[smb_direct(start(fixed = 4))]
    flags: DurableHandleV2Flags,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub struct SVHDXOpenDeviceContext {}

impl_smb_byte_size_for_bitflag!(ResponseLeaseFlags);
impl_smb_to_bytes_for_bitflag!(ResponseLeaseFlags);
impl_smb_from_bytes_for_bitflag!(ResponseLeaseFlags);

impl_tag_for_ctx!(DurableHandleResponse, DURABLE_HANDLE_RESPONSE_TAG);
impl_tag_for_ctx!(QueryMaximalAccessResponse, QUERY_MAXIMAL_ACCESS_RESPONSE_TAG);
impl_tag_for_ctx!(QueryOnDiskIDResponse, QUERY_ON_DISK_ID_RESPONSE_TAG);
impl_tag_for_ctx!(ResponseLease, RESPONSE_LEASE_TAG);
impl_tag_for_ctx!(ResponseLeaseV2, RESPONSE_LEASE_TAG);
impl_tag_for_ctx!(DurableHandleResponseV2, DURABLE_HANDLE_RESPONSE_V2_TAG);
impl_tag_for_ctx!(SVHDXOpenDeviceContext, SVHDX_OPEN_DEVICE_CONTEXT_RESPONSE_TAG);
