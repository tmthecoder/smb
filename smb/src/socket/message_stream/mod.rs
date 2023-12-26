use std::future::Future;

use tokio_util::sync::ReusableBoxFuture;

use smb_core::{SMBParseResult, SMBResult};
use smb_core::error::SMBError;

use crate::protocol::body::{LegacySMBBody, SMBBody};
use crate::protocol::header::{LegacySMBHeader, SMBSyncHeader};
use crate::protocol::message::{Message, SMBMessage};

// use crate::socket::message_stream::stream_async::SMBMessageStream;

#[cfg(not(feature = "async"))]
mod stream_sync;
#[cfg(feature = "async")]
mod stream_async;

pub trait SMBReadStream: Send + Sync {
    #[cfg(feature = "async")]
    fn read_message<'a>(&'a mut self, existing: &'a mut Vec<u8>) -> impl Future<Output=SMBParseResult<&[u8], SMBMessage<SMBSyncHeader, SMBBody>>> + Send;

    #[cfg(not(feature = "async"))]
    fn read_message<'a>(&'a mut self, existing: &'a mut Vec<u8>) -> SMBParseResult<&[u8], SMBMessage<SMBSyncHeader, SMBBody>>;
    #[cfg(not(feature = "async"))]
    fn messages(&mut self) -> SMBMessageIterator<Self> where Self: Sized;

    #[cfg(feature = "async")]
    fn messages(&mut self) -> SMBMessageStream<Self> where Self: Sized;
    fn read_message_inner(buffer: &[u8]) -> SMBParseResult<&[u8], SMBMessage<SMBSyncHeader, SMBBody>> {
        if let Some(pos) = buffer.iter().position(|x| *x == b'S') {
            if buffer[(pos)..].starts_with(b"SMB") {
                let result = SMBMessage::<SMBSyncHeader, SMBBody>::parse(&buffer[(pos - 1)..]);
                return if result.is_err() {
                    let (remaining, legacy_msg) = SMBMessage::<LegacySMBHeader, LegacySMBBody>::parse(&buffer[(pos - 1)..])?;
                    Ok((remaining, SMBMessage::<SMBSyncHeader, SMBBody>::from_legacy(legacy_msg).ok_or(SMBError::parse_error("Invalid legacy body"))?))
                } else {
                    result
                };
            }
        }
        Err(SMBError::parse_error("Unknwon error occurred while parsing message"))
    }
}

pub trait SMBWriteStream {
    #[cfg(feature = "async")]
    fn write_message<T: Message + Sync>(&mut self, message: &T) -> impl Future<Output=SMBResult<usize>> + Send;

    #[cfg(not(feature = "async"))]
    fn write_message<T: Message>(&mut self, message: &T) -> SMBResult<usize>;
}

pub struct SMBMessageIterator<'a, R: SMBReadStream> {
    pub(crate) reader: &'a mut R,
    pub(crate) buffer: Vec<u8>,
}

impl<'a, R: SMBReadStream> SMBMessageIterator<'a, R> {
    pub fn new(reader: &'a mut R) -> Self {
        Self {
            reader,
            buffer: Vec::new(),
        }
    }

    pub fn fields_mut(&mut self) -> (&mut R, &mut Vec<u8>) {
        (&mut self.reader, &mut self.buffer)
    }
}

#[cfg(feature = "async")]
pub struct SMBMessageStream<'a, T: SMBReadStream> {
    pub(crate) inner: ReusableBoxFuture<'a, (SMBResult<SMBMessage<SMBSyncHeader, SMBBody>>, SMBMessageIterator<'a, T>)>,
}

#[derive(Debug)]
pub struct SMBSocketConnection<R: SMBReadStream, W: SMBWriteStream> {
    name: String,
    read_stream: R,
    write_stream: W,
}

impl<R: SMBReadStream, W: SMBWriteStream> SMBSocketConnection<R, W> {
    pub fn new(name: String, read_stream: R, write_stream: W) -> Self {
        Self {
            name,
            read_stream,
            write_stream,
        }
    }

    pub fn messages(&mut self) -> SMBMessageIterator<R> {
        SMBMessageIterator::new(self.read())
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn read(&mut self) -> &mut R {
        &mut self.read_stream
    }

    pub fn write(&mut self) -> &mut W {
        &mut self.write_stream
    }

    pub fn streams(&mut self) -> (&mut R, &mut W) {
        (&mut self.read_stream, &mut self.write_stream)
    }

    pub fn into_streams(self) -> (R, W) {
        (self.read_stream, self.write_stream)
    }
}