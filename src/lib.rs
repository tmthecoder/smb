use std::io::Read;
use std::net::{IpAddr, TcpListener, TcpStream, ToSocketAddrs};

pub struct SMBServer {
    socket: TcpListener
}

pub struct SMBConnection {
    stream: TcpStream
}

pub enum SMBMessage {

}

pub struct SMBConnectionIterator<'a> {
    server: &'a SMBServer
}

pub struct SMBMessageIterator<'a> {
    stream: &'a mut SMBConnection
}

impl SMBServer {
    fn new<A: ToSocketAddrs>(addr: A) -> std::io::Result<Self> {
        let socket = TcpListener::bind(addr)?;
        Ok(SMBServer { socket })
    }
}

impl SMBServer {
    fn connections(&self) -> SMBConnectionIterator {
        SMBConnectionIterator { server: self }
    }
}

impl SMBConnection {
    fn messages(&mut self) -> SMBMessageIterator {
        SMBMessageIterator { stream: self }
    }
}

impl SMBMessage {
    fn parse(data: &[u8]) -> Option<Self> {
        None
    }
}

impl Iterator for SMBConnectionIterator<'_> {
    type Item = SMBConnection;

    fn next(&mut self) -> Option<Self::Item> {
        match self.server.socket.accept() {
            Ok((stream, _)) => {
                Some(SMBConnection { stream })
            },
            _ => None,
        }
    }
}

impl Iterator for SMBMessageIterator<'_> {
    type Item = SMBMessage;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buffer = [0_u8; 128];
        match self.stream.stream.read(&mut buffer) {
            Ok(read) => SMBMessage::parse(&buffer[0..read]),
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
