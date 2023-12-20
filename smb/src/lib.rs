#![feature(tuple_trait)]
extern crate core;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};

use crate::protocol::body::{LegacySMBBody, SMBBody};
use crate::protocol::header::{LegacySMBHeader, SMBSyncHeader};
use crate::protocol::message::{Message, SMBMessage};

pub mod protocol;
pub mod util;
pub mod server;
mod byte_helper;

#[derive(Debug)]
pub struct SMBListener {
    socket: TcpListener
}

impl Default for SMBListener {
    fn default() -> Self {
        Self::new("127.0.0.1:445").unwrap()
    }
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
    buffer: Vec<u8>,
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
            buffer: Vec::new(),
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

        if let Ok(read) = self.connection.stream.read(&mut buffer) {
            self.buffer.extend_from_slice(&buffer[..read]);
        }

        if let Some(pos) = self.buffer.iter().position(|x| *x == b'S') {
            if self.buffer[(pos)..].starts_with(b"SMB") {
                // println!("header: {:?}", SMBSyncHeader::smb_from_bytes(&buffer[(pos - 1)..read]));
                // println!("Current buffer: {:?}", &buffer[(pos)..]);
                let (carryover, message) = if let Ok((remaining, msg)) = SMBMessage::<SMBSyncHeader, SMBBody>::parse(&self.buffer[(pos - 1)..]) {
                    (remaining, msg)
                } else {
                    let (remaining, legacy_msg) = SMBMessage::<LegacySMBHeader, LegacySMBBody>::parse(&self.buffer[(pos - 1)..]).ok()?;
                    let m = SMBMessage::<SMBSyncHeader, SMBBody>::from_legacy(legacy_msg)?;
                    (remaining, m)
                };

                self.buffer = carryover.to_vec();
                return Some(message);
            }
        }

        None
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
