use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;
use std::ops::{Add, Deref, DerefMut};

use smb_core::error::SMBError;
use smb_core::SMBResult;

use crate::socket::message_stream::{SMBReadStream, SMBSocketConnection, SMBWriteStream};

#[cfg(not(feature = "async"))]
mod listener_sync;
#[cfg(feature = "async")]
mod listener_async;

pub trait SMBSocket<T: Send + Sync>: Send + Sync {
    type ReadStream: SMBReadStream + Send + Sync + Debug + 'static;
    type WriteStream: SMBWriteStream + Send + Sync + Debug + 'static;
    #[cfg(not(feature = "async"))]
    fn new_connection(&self) -> SMBResult<SMBSocketConnection<Self::ReadStream, Self::WriteStream>>;

    #[cfg(feature = "async")]
    fn new_connection(&self) -> impl Future<Output=SMBResult<SMBSocketConnection<Self::ReadStream, Self::WriteStream>>> + Send;
    #[cfg(not(feature = "async"))]
    fn new_socket(addr: T) -> SMBResult<Self> where Self: Sized {
        Err(SMBError::precondition_failed("Invalid socket address type"))
    }

    #[cfg(feature = "async")]
    async fn new_socket(addr: T) -> SMBResult<Self> where Self: Sized {
        Err(SMBError::precondition_failed("Invalid socket address type"))
    }
}

#[derive(Debug)]
pub struct SMBListener<Addrs: Send + Sync, Socket: SMBSocket<Addrs>> {
    pub(crate) socket: Socket,
    pub(crate) addrs_phantom: PhantomData<Addrs>,
}

pub struct SMBConnectionIterator<'a, Addrs: Send + Sync, Socket: SMBSocket<Addrs>> {
    server: &'a SMBListener<Addrs, Socket>,
}

impl<'a, Addrs: Send + Sync, Socket: SMBSocket<Addrs>> SMBConnectionIterator<'a, Addrs, Socket> {
    pub fn new(server: &'a SMBListener<Addrs, Socket>) -> Self {
        Self { server }
    }
}

impl<Addrs: Send + Sync, Socket: SMBSocket<Addrs>> Deref for SMBListener<Addrs, Socket> {
    type Target = Socket;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl<Addrs: Send + Sync, Socket: SMBSocket<Addrs>> DerefMut for SMBListener<Addrs, Socket> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}