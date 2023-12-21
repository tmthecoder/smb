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