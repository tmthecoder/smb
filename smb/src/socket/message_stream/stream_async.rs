use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::Stream;
use tokio_util::sync::ReusableBoxFuture;

use smb_core::{SMBParseResult, SMBResult};
use smb_core::error::SMBError;

use crate::protocol::body::SMBBody;
use crate::protocol::header::SMBSyncHeader;
use crate::protocol::message::{Message, SMBMessage};
use crate::socket::message_stream::{SMBMessageIterator, SMBMessageStream, SMBReadStream, SMBSocketConnection, SMBStream, SMBWriteStream};

async fn make_future<'a, T: SMBReadStream>(mut iterator: SMBMessageIterator<'a, T>) -> (SMBResult<SMBMessage<SMBSyncHeader, SMBBody>>, SMBMessageIterator<'a, T>) {
    let res = loop {
        match iterator.reader.read_message(&mut iterator.buffer).await {
            Ok(msg) => break Ok(msg),
            Err(SMBError::PayloadTooSmall(x)) => {
                println!("Buffer too small: {:?}", iterator.buffer);
            }
            Err(e) => {
                println!("Other error: {:?}, buf: {:02x?}", e, iterator.buffer);
                break Err(e);
            }
        }
    };
    let msg_res = if let Ok((bytes, msg)) = res {
        iterator.buffer = bytes.to_vec();
        Ok(msg)
    } else {
        Err(res.err().unwrap())
    };
    (msg_res, iterator)
}

impl<'a, T: SMBReadStream> SMBMessageStream<'a, T> {
    pub fn new(reader: &'a mut T) -> Self {
        let iterator = SMBMessageIterator::new(reader);
        let future = ReusableBoxFuture::new(make_future(iterator));
        Self {
            inner: future,
        }
    }
}

impl<Writer> SMBWriteStream for Writer where Writer: AsyncWriteExt + Unpin + Send + Sync + SMBStream {
    async fn write_message<T: Message + Sync>(&mut self, message: &T) -> SMBResult<usize> {
        let bytes = message.as_bytes();
        self.write_all(&bytes).await.map_err(SMBError::io_error)?;
        Ok(bytes.len())
    }
}

impl<Reader> SMBReadStream for Reader where Reader: AsyncReadExt + Unpin + Send + Sync + SMBStream {
    async fn read_message<'a>(&'a mut self, existing: &'a mut Vec<u8>) -> SMBParseResult<&'a [u8], SMBMessage<SMBSyncHeader, SMBBody>> {
        let mut buffer = [0u8; 512];
        if let Ok(read) = self.read(&mut buffer).await {
            existing.extend_from_slice(&buffer[..read]);
        }
        Self::read_message_inner(existing)
    }

    fn messages(&mut self) -> SMBMessageStream<Self> where Self: Sized {
        SMBMessageStream::new(self)
    }
}

impl<R: SMBReadStream, W: SMBWriteStream> SMBSocketConnection<R, W> {
    pub async fn send_message<T: Message + Sync>(&mut self, message: &T) -> SMBResult<usize> {
        self.write().write_message(message).await
    }
}

impl<'a, R: SMBReadStream> Stream for SMBMessageStream<'a, R> {
    type Item = SMBMessage<SMBSyncHeader, SMBBody>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let (res, iterator) = ready!(self.inner.poll(cx));
        self.inner.set(make_future(iterator));
        match res {
            Ok(message) => Poll::Ready(Some(message)),
            Err(_) => Poll::Ready(None),
        }
    }
}