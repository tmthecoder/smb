use std::marker::PhantomData;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};

use smb_core::error::SMBError;
use smb_core::SMBResult;

use crate::socket::listener::{SMBConnectionIterator, SMBListener, SMBSocket};
use crate::socket::message_stream::SMBSocketConnection;

impl<Addrs: Send + Sync, Socket: SMBSocket<Addrs>> SMBListener<Addrs, Socket> {
    pub fn new(addr: Addrs) -> SMBResult<Self> {
        let socket = Socket::new_socket(addr)?;
        Ok(SMBListener { socket, addrs_phantom: PhantomData })
    }
}

impl<T> SMBSocket<T> for TcpListener where T: ToSocketAddrs + Send + Sync {
    type ReadStream = TcpStream;
    type WriteStream = TcpStream;

    fn new_connection(&self) -> SMBResult<SMBSocketConnection<Self::ReadStream, Self::WriteStream>> {
        match self.accept() {
            Ok((read, addr)) => {
                let write = read.try_clone().map_err(SMBError::io_error)?;
                Ok(SMBSocketConnection::new(addr.to_string(), read, write))
            }
            Err(e) => Err(SMBError::io_error(e))
        }
    }
    fn new_socket(addr: T) -> SMBResult<Self> where Self: Sized {
        Self::bind(addr).map_err(SMBError::io_error)
    }
}

impl<Addrs: Send + Sync, Socket: SMBSocket<Addrs>> Iterator for SMBConnectionIterator<'_, Addrs, Socket> {
    type Item = SMBSocketConnection<Socket::ReadStream, Socket::WriteStream>;

    fn next(&mut self) -> Option<Self::Item> {
        self.server.new_connection().ok()
    }
}

impl<Addrs: Send + Sync, Socket: SMBSocket<Addrs>> SMBListener<Addrs, Socket> {
    pub fn connections(&self) -> SMBConnectionIterator<Addrs, Socket> {
        SMBConnectionIterator { server: self }
    }
}