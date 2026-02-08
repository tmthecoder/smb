use std::future::Future;
use std::io::ErrorKind;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio_stream::Stream;
use tokio_util::sync::ReusableBoxFuture;

use smb_core::error::SMBError;
use smb_core::SMBResult;

use crate::socket::listener::{SMBConnectionIterator, SMBListener, SMBSocket};
use crate::socket::message_stream::{SMBSocketConnection, SMBStream};

impl<T> SMBSocket<T> for TcpListener where T: ToSocketAddrs + Send + Sync {
    type ReadStream = OwnedReadHalf;
    type WriteStream = OwnedWriteHalf;

    async fn new_connection(&self) -> SMBResult<SMBSocketConnection<Self::ReadStream, Self::WriteStream>> {
        match self.accept().await {
            Ok((stream, addr)) => {
                let (read, write) = stream.into_split();
                Ok(SMBSocketConnection::new(addr.to_string(), read, write))
            }
            Err(e) => Err(SMBError::io_error(e))
        }
    }

    async fn new_socket(addr: T) -> SMBResult<Self> where Self: Sized {
        Self::bind(addr).await.map_err(SMBError::io_error)
    }
}

impl SMBStream for OwnedReadHalf {
    async fn close_stream(&mut self) -> SMBResult<()> {
        Err(SMBError::io_error(io::Error::new(ErrorKind::Unsupported, "Invalid operation")))
    }
}

impl SMBStream for OwnedWriteHalf {
    async fn close_stream(&mut self) -> SMBResult<()> {
        self.shutdown().await.map_err(SMBError::io_error)
    }
}

type SMBConnectionResult<R, W> = SMBResult<SMBSocketConnection<R, W>>;

type SMBConnectionStreamResult<'a, Addrs, Socket> = (SMBConnectionResult<<Socket as SMBSocket<Addrs>>::ReadStream, <Socket as SMBSocket<Addrs>>::WriteStream>, SMBConnectionIterator<'a, Addrs, Socket>);

pub struct SMBConnectionStream<'a, Addrs: Send + Sync, Socket: SMBSocket<Addrs>> {
    inner: ReusableBoxFuture<'a, SMBConnectionStreamResult<'a, Addrs, Socket>>,
}

async fn make_future<'a, Addrs: Send + Sync, Socket: SMBSocket<Addrs>>(mut iterator: SMBConnectionIterator<'a, Addrs, Socket>) -> SMBConnectionStreamResult<'a, Addrs, Socket> {
    let res = iterator.server.new_connection().await;
    (res, iterator)
}

impl<'a, Addrs: Send + Sync, Socket: SMBSocket<Addrs>> SMBConnectionStream<'a, Addrs, Socket> {
    pub fn new(listener: &'a SMBListener<Addrs, Socket>) -> Self {
        let iterator = SMBConnectionIterator::new(listener);
        let inner = ReusableBoxFuture::new(make_future(iterator));
        Self {
            inner
        }
    }
}

impl<Addrs: Send + Sync, Socket: SMBSocket<Addrs>> Stream for SMBConnectionStream<'_, Addrs, Socket> {
    type Item = SMBSocketConnection<Socket::ReadStream, Socket::WriteStream>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let (res, iterator) = ready!(self.inner.poll(cx));
        self.inner.set(make_future(iterator));
        match res {
            Ok(message) => Poll::Ready(Some(message)),
            Err(_) => Poll::Ready(None),
        }
    }
}

impl<Addrs: Send + Sync, Socket: SMBSocket<Addrs>> SMBListener<Addrs, Socket> {
    pub async fn new(addr: Addrs) -> SMBResult<Self> {
        let socket = Socket::new_socket(addr).await?;
        Ok(SMBListener { socket, addrs_phantom: PhantomData })
    }
}

impl<Addrs: Send + Sync, Socket: SMBSocket<Addrs>> SMBListener<Addrs, Socket> {
    pub fn connections(&self) -> SMBConnectionStream<'_, Addrs, Socket> {
        SMBConnectionStream::new(self)
    }
}