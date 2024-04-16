use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBEnumFromBytes, SMBFromBytes, SMBToBytes};

#[derive(SMBEnumFromBytes, Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, SMBByteSize, SMBToBytes)]
pub enum SMBIoCtlMethod {
    #[smb_discriminator(value = 0x00060194)]
    #[smb_direct(start(fixed = 0))]
    DfsGetReferrals(DfsGetReferrals),
    #[smb_discriminator(value = 0x011400C)]
    #[smb_direct(start(fixed = 0))]
    PipePeek(PipePeek),
    #[smb_discriminator(value = 0x0110018)]
    #[smb_direct(start(fixed = 0))]
    PipeWait(PipeWait),
    #[smb_discriminator(value = 0x011C017)]
    #[smb_direct(start(fixed = 0))]
    PipeTransceive(PipeTransceive),
    #[smb_discriminator(value = 0x001440F2)]
    #[smb_direct(start(fixed = 0))]
    SrvCopyChunk(SrvCopyChunk),
    #[smb_discriminator(value = 0x00140198)]
    #[smb_direct(start(fixed = 0))]
    SrvEnumerateSnapshots(SrvEnumerateSnapshots),
    #[smb_discriminator(value = 0x00140194)]
    #[smb_direct(start(fixed = 0))]
    SrvRequestResumeKey(SrvRequestResumeKey),
    #[smb_discriminator(value = 0x00140190)]
    #[smb_direct(start(fixed = 0))]
    SrvReadHash(SrvReadHash),
    #[smb_discriminator(value = 0x001480F2)]
    #[smb_direct(start(fixed = 0))]
    SrvCopyChunkWrite(SrvCopyChunkWrite),
    #[smb_discriminator(value = 0x001401D4)]
    #[smb_direct(start(fixed = 0))]
    LmrRequestResiliency(LmrRequestResiliency),
    #[smb_discriminator(value = 0x001401FC)]
    #[smb_direct(start(fixed = 0))]
    NetworkInterfaceInfo(NetworkInterfaceInfo),
    #[smb_discriminator(value = 0x000900A4)]
    #[smb_direct(start(fixed = 0))]
    SetReparsePoint(SetReparsePoint),
    #[smb_discriminator(value = 0x000601B0)]
    #[smb_direct(start(fixed = 0))]
    DfsGetReferralsEx(DfsGetReferralsEx),
    #[smb_discriminator(value = 0x00098208)]
    #[smb_direct(start(fixed = 0))]
    FileLevelTrim(FileLevelTrip),
    #[smb_discriminator(value = 0x00140204)]
    #[smb_direct(start(fixed = 0))]
    ValidateNegotiateInfo(ValidateNegotiateInfo),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, SMBByteSize, SMBToBytes, SMBFromBytes)]
pub struct DfsGetReferrals {}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, SMBByteSize, SMBToBytes, SMBFromBytes)]
pub struct PipePeek {}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, SMBByteSize, SMBToBytes, SMBFromBytes)]
pub struct PipeWait {}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, SMBByteSize, SMBToBytes, SMBFromBytes)]
pub struct PipeTransceive {}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, SMBByteSize, SMBToBytes, SMBFromBytes)]
pub struct SrvCopyChunk {}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, SMBByteSize, SMBToBytes, SMBFromBytes)]
pub struct SrvEnumerateSnapshots {}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, SMBByteSize, SMBToBytes, SMBFromBytes)]
pub struct SrvRequestResumeKey {}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, SMBByteSize, SMBToBytes, SMBFromBytes)]
pub struct SrvReadHash {}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, SMBByteSize, SMBToBytes, SMBFromBytes)]
pub struct SrvCopyChunkWrite {}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, SMBByteSize, SMBToBytes, SMBFromBytes)]
pub struct LmrRequestResiliency {}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, SMBByteSize, SMBToBytes, SMBFromBytes)]
pub struct NetworkInterfaceInfo {}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, SMBByteSize, SMBToBytes, SMBFromBytes)]
pub struct SetReparsePoint {}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, SMBByteSize, SMBToBytes, SMBFromBytes)]
pub struct DfsGetReferralsEx {}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, SMBByteSize, SMBToBytes, SMBFromBytes)]
pub struct FileLevelTrip {}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, SMBByteSize, SMBToBytes, SMBFromBytes)]
pub struct ValidateNegotiateInfo {}

