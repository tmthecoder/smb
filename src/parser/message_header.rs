struct SMBHeader {
    command: SMBCommandCode,
    status: SMBStatus,
    flags: SMBFlags,
    flags2: SMBFlags2,
    extra: SMBExtra,
    tid: u16,
    pid: u16,
    uid: u16,
    mid: u16
}

#[repr(u8)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
pub enum SMBCommandCode {
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

enum SMBStatus {
    NTStatus(NTStatusLevel),
    DosError(char, char, u16)
}

struct NTStatusCode {
    level: NTStatusLevel,
}

#[repr(u8)]
enum NTStatusLevel {
    Success,
    Information,
    Warning,
    Error
}

enum SMBFlags {

}

enum SMBFlags2 {

}

enum SMBExtra {

}

impl SMBCommandCode {
    fn parse(data: &[u8]) -> Option<Self> {
        println!("data: {:?} len: {}", data, data.len());
        if let Some(pos) = data.iter().position(|x| *x == 'S' as u8) {
            if data[pos..].starts_with(b"SMB") {
                println!("GOT SMB: {}", pos);
                return SMBCommandCode::try_from(data[pos + 3]).ok()
            }
        }
        None
    }
}