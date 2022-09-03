pub mod header;
pub mod parameters;
pub mod data;
pub mod body;
pub mod message;
mod byte_helper;

use std::io::Read;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use crate::body::SMBBody;
use crate::header::SMBHeader;
use crate::message::SMBMessage;

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
    connection: &'a mut SMBConnection,
    carryover: [u8; 128],
    carryover_len: usize
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
        SMBMessageIterator {
            connection: self,
            carryover: [0; 128],
            carryover_len: 0
        }
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
        println!("In next: {} W carryover: {:?}", self.carryover_len, self.carryover);
        if self.carryover_len >= 32 && self.carryover.starts_with(b"SMB") {
            let header = SMBHeader::from_bytes(&self.carryover)?;
            return Some(SMBMessage { header, body: SMBBody::None });
        }
        match self.connection.stream.read(&mut buffer) {
            Ok(read) => {
                println!("buffer: {:?}", buffer);
                if let Some(pos) = buffer.iter().position(|x| *x == b'S') {
                    if buffer[pos..].starts_with(b"SMB") {
                        let (message, carryover) = SMBMessage::from_bytes(&buffer[(pos + 3)..read])?;
                        for (idx, byte) in carryover.iter().enumerate() {
                            self.carryover[self.carryover_len + idx] = *byte;
                        }
                        self.carryover_len += carryover.len();
                        return Some(message);
                    }
                }
                None
            }
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
