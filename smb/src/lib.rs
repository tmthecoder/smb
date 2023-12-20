#![feature(tuple_trait)]
extern crate core;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};

use smb_core::SMBFromBytes;

use crate::protocol::body::{LegacySMBBody, SMBBody};
use crate::protocol::header::{Header, LegacySMBHeader, SMBSyncHeader};
use crate::protocol::message::{Message, SMBMessage};

pub mod protocol;
pub mod util;
pub mod server;
mod byte_helper;

#[derive(Debug)]
pub struct SMBListener {
    socket: TcpListener
}

#[derive(Debug)]
pub struct SMBMessageStream {
    stream: TcpStream
}

pub struct SMBMessageStreamIterator<'a> {
    server: &'a SMBListener
}

pub struct SMBMessageIterator<'a> {
    connection: &'a mut SMBMessageStream,
    carryover: [u8; 512],
    carryover_len: usize
}

impl SMBListener {
    pub fn new<A: ToSocketAddrs>(addr: A) -> std::io::Result<Self> {
        let socket = TcpListener::bind(addr)?;
        Ok(SMBListener { socket })
    }
}

impl SMBListener {
    pub fn connections(&self) -> SMBMessageStreamIterator {
        SMBMessageStreamIterator { server: self }
    }
}

impl SMBMessageStream {
    pub fn messages(&mut self) -> SMBMessageIterator {
        SMBMessageIterator {
            connection: self,
            carryover: [0; 512],
            carryover_len: 0
        }
    }

    pub fn try_clone(&self) -> std::io::Result<Self> {
        Ok(SMBMessageStream {
            stream: self.stream.try_clone()?
        })
    }

    pub fn send_message<T: Message>(&mut self, message: T) -> std::io::Result<()> {
        self.stream.write_all(&message.as_bytes())
    }
}

impl Iterator for SMBMessageStreamIterator<'_> {
    type Item = SMBMessageStream;

    fn next(&mut self) -> Option<Self::Item> {
        match self.server.socket.accept() {
            Ok((stream, _)) => {
                Some(SMBMessageStream { stream })
            },
            _ => None,
        }
    }
}

impl Iterator for SMBMessageIterator<'_> {
    type Item = SMBMessage<SMBSyncHeader, SMBBody>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buffer = [0_u8; 512];
        println!("In next: {} W carryover: {:?}", self.carryover_len, self.carryover);
        if self.carryover_len >= 32 && self.carryover.starts_with(b"SMB") {
            let (_, (header, _)) = SMBSyncHeader::parse(&self.carryover).ok()?;
            return Some(SMBMessage { header, body: SMBBody::None });
        }
        match self.connection.stream.read(&mut buffer) {
            Ok(read) => {
                if let Some(pos) = buffer.iter().position(|x| *x == b'S') {
                    if buffer[(pos)..].starts_with(b"SMB") {
                        println!("header: {:?}", SMBSyncHeader::smb_from_bytes(&buffer[(pos - 1)..read]));
                        println!("Current buffer: {:?}", &buffer[(pos)..]);
                        let (carryover, message) = if let Ok((remaining, msg)) = SMBMessage::<SMBSyncHeader, SMBBody>::parse(&buffer[(pos-1)..read]) {
                            (remaining, msg)
                        } else {
                            let (remaining, legacy_msg) = SMBMessage::<LegacySMBHeader, LegacySMBBody>::parse(&buffer[(pos-1)..read]).ok()?;
                            let m = SMBMessage::<SMBSyncHeader, SMBBody>::from_legacy(legacy_msg)?;
                            (remaining, m)
                        };
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
