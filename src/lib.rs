mod parser;

use num_enum::TryFromPrimitive;
use std::io::Read;
use std::net::{IpAddr, TcpListener, TcpStream, ToSocketAddrs};

#[derive(Debug)]
pub struct SMBServer {
    socket: TcpListener
}

#[derive(Debug)]
pub struct SMBConnection {
    stream: TcpStream
}

#[repr(u8)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
pub enum SMBMessageCommandCode {
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

pub struct SMBConnectionIterator<'a> {
    server: &'a SMBServer
}

pub struct SMBMessageIterator<'a> {
    stream: &'a mut SMBConnection
}

impl SMBServer {
    pub fn new<A: ToSocketAddrs>(addr: A) -> std::io::Result<Self> {
        let socket = TcpListener::bind(addr)?;
        Ok(SMBServer { socket })
    }
}

impl SMBServer {
    pub fn connections(&self) -> SMBConnectionIterator {
        SMBConnectionIterator { server: self }
    }
}

impl SMBConnection {
    pub fn messages(&mut self) -> SMBMessageIterator {
        SMBMessageIterator { stream: self }
    }
}

impl SMBMessageCommandCode {
    fn parse(data: &[u8]) -> Option<Self> {
        println!("data: {:?} len: {}", data, data.len());
        if let Some(pos) = data.iter().position(|x| *x == 'S' as u8) {
            if data[pos..].starts_with(b"SMB") {
                println!("GOT SMB: {}", pos);
                return SMBMessageCommandCode::try_from(data[pos + 3]).ok()
            }
        }
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
    type Item = SMBMessageCommandCode;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buffer = [0_u8; 128];
        let mut carryover = [0_u8; 128];
        match self.stream.stream.read(&mut buffer) {
            Ok(read) => SMBMessageCommandCode::parse(&buffer[0..read]),
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
