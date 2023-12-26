use std::io::{Read, Write};

use smb_core::{SMBParseResult, SMBResult};
use smb_core::error::SMBError;

use crate::protocol::body::SMBBody;
use crate::protocol::header::SMBSyncHeader;
use crate::protocol::message::{Message, SMBMessage};
use crate::socket::message_stream::{SMBMessageIterator, SMBReadStream, SMBSocketConnection, SMBWriteStream};

impl<Reader> SMBReadStream for Reader where Reader: Read + Send + Sync {
    fn read_message<'a>(&'a mut self, existing: &'a mut Vec<u8>) -> SMBParseResult<&[u8], SMBMessage<SMBSyncHeader, SMBBody>> {
        let mut buffer = [0_u8; 512];

        if let Ok(read) = self.read(&mut buffer) {
            existing.extend_from_slice(&buffer[..read]);
        }

        Self::read_message_inner(existing)
    }

    fn messages(&mut self) -> SMBMessageIterator<Self> where Self: Sized {
        SMBMessageIterator::new(self)
    }
}

impl<Writer> SMBWriteStream for Writer where Writer: Write {
    fn write_message<T: Message>(&mut self, message: &T) -> SMBResult<usize> {
        let bytes = message.as_bytes();
        self.write_all(&bytes).map_err(SMBError::io_error)?;
        Ok(bytes.len())
    }
}

impl<R: SMBReadStream, W: SMBWriteStream> SMBSocketConnection<R, W> {
    pub fn send_message<T: Message>(&mut self, message: &T) -> SMBResult<usize> {
        self.write().write_message(message)
    }
}

impl<R: SMBReadStream> Iterator for SMBMessageIterator<'_, R> {
    type Item = SMBMessage<SMBSyncHeader, SMBBody>;

    fn next(&mut self) -> Option<Self::Item> {
        let (remaining, message) = self.reader.read_message(&mut self.buffer).ok()?;
        self.buffer = remaining.to_vec();
        Some(message)
    }
}