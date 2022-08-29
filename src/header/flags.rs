use bitflags::bitflags;

bitflags! {
    pub struct SMBFlags: u8 {
        const SERVER_TO_REDIR = 0b10000000;
        const REQUEST_BATCH_OPLOCK = 0b1000000;
        const REQUEST_OPLOCK = 0b100000;
        const CANONICAL_PATHNAMES = 0b10000;
        const CASELESS_PATHNAMES = 0b1000;
        const CLIENT_BUF_AVAIL = 0b100;
        const SUPPORT_LOCKREAD = 0b1;
    }
}

impl Default for SMBFlags {
    fn default() -> Self {
        SMBFlags::CANONICAL_PATHNAMES | SMBFlags::CASELESS_PATHNAMES
    }
}

impl SMBFlags {
    pub fn clear(&mut self) {
        self.bits = 0;
    }
}