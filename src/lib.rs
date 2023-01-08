extern crate core;

pub mod protocol;
pub mod util;
// pub mod server;
mod byte_helper;
mod gss_helper;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use nom::bytes::complete::tag;
use nom::error::Error;
use crate::protocol::body::{LegacySMBBody, SMBBody};
use crate::protocol::header::{Header, LegacySMBHeader, SMBSyncHeader};
use crate::protocol::message::{Message, SMBMessage};

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
            let (header, _) = SMBSyncHeader::from_bytes(&self.carryover)?;
            return Some(SMBMessage { header, body: SMBBody::None });
        }
        match self.connection.stream.read(&mut buffer) {
            Ok(read) => {
                println!("buffer: {:?}", buffer);
                let res = tag::<_, _, Error<_>>(b"SMB")(&buffer[0..]);
                if let Some(pos) = buffer.iter().position(|x| *x == b'S') {
                    if buffer[(pos)..].starts_with(b"SMB") {
                        let carryover;
                        let message;
                        if let Some((m, c)) = SMBMessage::<SMBSyncHeader, SMBBody>::from_bytes_assert_body(&buffer[(pos-1)..read]) {
                            carryover = c;
                            message = m;
                        } else {
                            let (legacy, c) = SMBMessage::<LegacySMBHeader, LegacySMBBody>::from_bytes_assert_body(&buffer[(pos-1)..read])?;
                            carryover = c;
                            let m = SMBMessage::<SMBSyncHeader, SMBBody>::from_legacy(legacy)?;
                            message = m;
                        }
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
