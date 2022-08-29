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

// impl Iterator for SMBMessageIterator<'_> {
//     type Item = SMBMessageCommandCode;
//
//     fn next(&mut self) -> Option<Self::Item> {
//         let mut buffer = [0_u8; 128];
//         let mut carryover = [0_u8; 128];
//         match self.stream.stream.read(&mut buffer) {
//             Ok(read) => SMBMessageCommandCode::parse(&buffer[0..read]),
//             _ => None
//         }
//     }
// }

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
