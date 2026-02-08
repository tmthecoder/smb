use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, IntoPrimitive, Serialize, Deserialize, Clone, Copy, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub enum SMBCommandCode {
    Negotiate = 0x0,
    SessionSetup,
    LogOff,
    TreeConnect,
    TreeDisconnect,
    Create,
    Close,
    Flush,
    Read,
    Write,
    Lock,
    IOCTL,
    Cancel,
    Echo,
    QueryDirectory,
    ChangeNotify,
    QueryInfo,
    SetInfo,
    OplockBreak,
    LegacyNegotiate
}

impl Into<u64> for SMBCommandCode {
    fn into(self) -> u64 {
        self as u16 as u64
    }
}

#[repr(u8)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, IntoPrimitive, Serialize, Deserialize, Clone, Copy, SMBFromBytes, SMBByteSize, SMBToBytes)]
pub enum LegacySMBCommandCode {
    CreateDirectory,
    DeleteDirectory,
    Open,
    Create,
    Close,
    Flush,
    Delete,
    Rename,
    QueryInformation,
    SetInformation,
    Read,
    Write,
    LockByteRange,
    UnlockByteRange,
    CreateTemporary,
    CreateNew,
    CheckDirectory,
    ProcessExit,
    Seek,
    LockAndRead,
    WriteAndUnlock,
    ReadRaw = 0x1A,
    ReadMPX,
    ReadMPXSecondary,
    WriteRaw,
    WriteMPX,
    WriteMPXSecondary,
    WriteComplete,
    QueryServer,
    SetInformation2,
    QueryInformation2,
    LockingANDX,
    Transaction,
    TransactionSecondary,
    IOCTL,
    IOCTLSecondary,
    Copy,
    Move,
    Echo,
    WriteAndClose,
    OpenANDX,
    ReadANDX,
    WriteANDX,
    NewFileSize,
    CloseAndTreeDisc,
    Transaction2,
    Transaction2Secondary,
    FindClose2,
    FindNotifyClose,
    TreeConnect = 0x70,
    TreeDisconnect,
    Negotiate,
    SessionSetupANDX,
    LogoffANDX,
    TreeConnectANDX,
    QueryInformationDisk = 0x80,
    Search,
    Find,
    FindUnique,
    FindClose,
    NTTransact = 0xA0,
    NTTransactSecondary,
    NTCreateANDX,
    NTCancel,
    NTRename,
    OpenPrintFile = 0xC0,
    WritePrintFile,
    ClosePrintFile,
    GetPrintQueue,
    ReadBulk = 0xD9,
    WriteBulkData
}

impl Into<u64> for LegacySMBCommandCode {
    fn into(self) -> u64 {
        self as u8 as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MS-SMB2 2.2.1: All command codes should have the correct numeric values.
    #[test]
    fn command_codes_match_spec() {
        assert_eq!(SMBCommandCode::Negotiate as u16, 0x0000);
        assert_eq!(SMBCommandCode::SessionSetup as u16, 0x0001);
        assert_eq!(SMBCommandCode::LogOff as u16, 0x0002);
        assert_eq!(SMBCommandCode::TreeConnect as u16, 0x0003);
        assert_eq!(SMBCommandCode::TreeDisconnect as u16, 0x0004);
        assert_eq!(SMBCommandCode::Create as u16, 0x0005);
        assert_eq!(SMBCommandCode::Close as u16, 0x0006);
        assert_eq!(SMBCommandCode::Flush as u16, 0x0007);
        assert_eq!(SMBCommandCode::Read as u16, 0x0008);
        assert_eq!(SMBCommandCode::Write as u16, 0x0009);
        assert_eq!(SMBCommandCode::Lock as u16, 0x000A);
        assert_eq!(SMBCommandCode::IOCTL as u16, 0x000B);
        assert_eq!(SMBCommandCode::Cancel as u16, 0x000C);
        assert_eq!(SMBCommandCode::Echo as u16, 0x000D);
        assert_eq!(SMBCommandCode::QueryDirectory as u16, 0x000E);
        assert_eq!(SMBCommandCode::ChangeNotify as u16, 0x000F);
        assert_eq!(SMBCommandCode::QueryInfo as u16, 0x0010);
        assert_eq!(SMBCommandCode::SetInfo as u16, 0x0011);
        assert_eq!(SMBCommandCode::OplockBreak as u16, 0x0012);
    }
}