use std::future::Future;

use tokio_util::sync::ReusableBoxFuture;

use smb_core::{SMBFromBytes, SMBParseResult, SMBResult};
use smb_core::error::SMBError;

use crate::protocol::body::{LegacySMBBody, SMBBody};
use crate::protocol::body::error::SMBErrorResponse;
use crate::protocol::header::{Header, LegacySMBHeader, SMBSyncHeader};
use crate::protocol::message::{Message, SMBMessage};

// use crate::socket::message_stream::stream_async::SMBMessageStream;

#[cfg(not(feature = "async"))]
mod stream_sync;
#[cfg(feature = "async")]
mod stream_async;

pub trait SMBReadStream: SMBStream {
    #[cfg(feature = "async")]
    fn read_message<'a>(&'a mut self, existing: &'a mut Vec<u8>) -> impl Future<Output=SMBParseResult<&[u8], SMBMessage<SMBSyncHeader, SMBBody>>> + Send;

    #[cfg(not(feature = "async"))]
    fn read_message<'a>(&'a mut self, existing: &'a mut Vec<u8>) -> SMBParseResult<&[u8], SMBMessage<SMBSyncHeader, SMBBody>>;
    #[cfg(not(feature = "async"))]
    fn messages(&mut self) -> SMBMessageIterator<Self> where Self: Sized;

    #[cfg(feature = "async")]
    fn messages(&mut self) -> SMBMessageStream<Self> where Self: Sized;
    fn read_message_inner(buffer: &[u8]) -> SMBParseResult<&[u8], SMBMessage<SMBSyncHeader, SMBBody>> {
        println!("in inner read");
        if let Some(pos) = buffer.iter().position(|x| *x == b'S') {
            println!("found s at pos: {}", pos);
            if buffer[(pos)..].starts_with(b"SMB") {
                println!("found smb");
                let smb_start = pos - 1;
                let result = SMBMessage::<SMBSyncHeader, SMBBody>::parse(&buffer[smb_start..]);
                return match result {
                    Ok(r) => Ok(r),
                    Err(_) => {
                        // Try legacy parse first
                        if let Ok((remaining, legacy_msg)) = SMBMessage::<LegacySMBHeader, LegacySMBBody>::parse(&buffer[smb_start..]) {
                            return Ok((remaining, SMBMessage::<SMBSyncHeader, SMBBody>::from_legacy(legacy_msg)
                                .ok_or(SMBError::parse_error("Invalid legacy body"))?));
                        }
                        // Body parse failed — try header-only parse and return an ErrorResponse
                        // so the connection handler can send a proper error back to the client
                        if let Ok((remaining, mut header)) = SMBSyncHeader::smb_from_bytes(&buffer[smb_start..]) {
                            println!("Header-only parse succeeded for command {:?}, returning ErrorResponse", header.command);
                            header.channel_sequence = smb_core::nt_status::NTStatus::NotSupported as u32;
                            let body = SMBBody::ErrorResponse(SMBErrorResponse::new());
                            Ok((&buffer[buffer.len()..], SMBMessage::new(header, body)))
                        } else {
                            Err(SMBError::parse_error("Failed to parse header"))
                        }
                    }
                };
            }
        }
        Err(SMBError::parse_error("Unknown error occurred while parsing message"))
    }
}

pub trait SMBWriteStream: SMBStream {
    #[cfg(feature = "async")]
    fn write_message<T: Message + Sync>(&mut self, message: &T) -> impl Future<Output=SMBResult<usize>> + Send;

    #[cfg(not(feature = "async"))]
    fn write_message<T: Message>(&mut self, message: &T) -> SMBResult<usize>;
}

pub trait SMBStream: Send + Sync {
    #[cfg(feature = "async")]
    fn close_stream(&mut self) -> impl Future<Output=SMBResult<()>> + Send;
    #[cfg(not(feature = "async"))]
    fn close_stream(&mut self) -> SMBResult<()>;
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