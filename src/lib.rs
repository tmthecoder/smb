use std::io::Read;
use std::net::{IpAddr, TcpListener, TcpStream, ToSocketAddrs};

pub struct SMBServer {
    socket: TcpListener
}

pub struct SMBConnection {
    stream: TcpStream
}

pub enum SMBMessage {
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
    ReadRaw,
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
    TreeConnect,
    TreeDisconnect,
    Negotiate,
    SessionSetupANDX,
    LogoffANDX,
    TreeConnectANDX,
    QueryInformationDisk,
    Search,
    Find,
    FindUnique,
    FindClose,
    NTTransact,
    NTTransactSecondary,
    NTCreateANDX,
    NTCancel,
    NTRename,
    OpenPrintFile,
    WritePrintFile,
    ClosePrintFile,
    GetPrintQueue,
    ReadBulk,
    WriteBulkData
}

pub struct SMBConnectionIterator<'a> {
    server: &'a SMBServer
}

pub struct SMBMessageIterator<'a> {
    stream: &'a mut SMBConnection
}

impl SMBServer {
    fn new<A: ToSocketAddrs>(addr: A) -> std::io::Result<Self> {
        let socket = TcpListener::bind(addr)?;
        Ok(SMBServer { socket })
    }
}

impl SMBServer {
    fn connections(&self) -> SMBConnectionIterator {
        SMBConnectionIterator { server: self }
    }
}

impl SMBConnection {
    fn messages(&mut self) -> SMBMessageIterator {
        SMBMessageIterator { stream: self }
    }
}

impl SMBMessage {
    fn parse(data: &[u8]) -> Option<Self> {
        None
    }
}

impl Iterator for SMBConnectionIterator<'_> {
    type Item = SMBConnection;

    fn next(&mut self) -> Option<Self::Item> {
        match self.server.socket.accept() {
            Ok((stream, _)) => {
                Some(SMBConnection { stream })
            },
            _ => None,
        }
    }
}

impl Iterator for SMBMessageIterator<'_> {
    type Item = SMBMessage;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buffer = [0_u8; 128];
        match self.stream.stream.read(&mut buffer) {
            Ok(read) => SMBMessage::parse(&buffer[0..read]),
            _ => None
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
