use smb_reader::protocol::body::tree_connect::{SMBAccessMask, SMBDirectoryAccessMask};
use smb_reader::server::{SMBServerBuilder, SMBShare};

const NTLM_ID: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
const SPNEGO_ID: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

fn main() -> anyhow::Result<()> {
    let share = SMBShare::disk("someshare".into(), file_allowed, get_file_perms);
    let builder = SMBServerBuilder::default()
        .anonymous_access(true)
        .unencrypted_access(true)
        .add_share("test", share)
        .listener_address("127.0.0.1:50122")?;
    let mut server = builder.build()?;
    server.start()
}

fn file_allowed(test: u64) -> bool {
    true
}

fn get_file_perms(test: u64) -> SMBAccessMask {
    SMBAccessMask::Directory(SMBDirectoryAccessMask::GENERIC_ALL)
}