use bitflags::bitflags;

bitflags! {
    pub struct SMBFlags: u8 {
        const SERVER_TO_REDIR = 0b10000000;
        const REQUEST_BATCH_OPLOCK = 0b01000000;
        const REQUEST_OPLOCK = 0b00100000;
        const CANONICAL_PATHNAMES = 0b00010000;
        const CASELESS_PATHNAMES = 0b00001000;
        const CLIENT_BUF_AVAIL = 0b00000100;
        const SUPPORT_LOCKREAD = 0b0000001;
    }
}

impl SMBFlags {
    pub fn clear(&mut self) {
        self.bits = 0;
    }
}