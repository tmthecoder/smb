#[cfg(not(feature = "async"))]
use std::net::TcpListener;

#[cfg(feature = "async")]
use tokio::net::TcpListener;

use smb_core::SMBResult;
use smb_reader::protocol::body::tree_connect::access_mask::{SMBAccessMask, SMBDirectoryAccessMask};
use smb_reader::server::{DefaultShare, SMBServerBuilder, StartSMBServer};
use smb_reader::util::auth::ntlm::NTLMAuthProvider;
use smb_reader::util::auth::User;

const NTLM_ID: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
const SPNEGO_ID: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

// type BaseFSType = SMBFileSystemShare<String, SMBFileSystemHandle>;

#[cfg(feature = "async")]
#[tokio::main]
async fn main() -> SMBResult<()> {
    // let share = SMBFileSystemShare::<_, _, _, Box<dyn ResourceHandle>>::root("TEST".into(), file_allowed, get_file_perms);
    let builder = SMBServerBuilder::<_, TcpListener, NTLMAuthProvider, DefaultShare<NTLMAuthProvider>, _>::default()
        .anonymous_access(true)
        .unencrypted_access(true)
        .require_message_signing(false)
        .encrypt_data(false)
        .add_fs_share("test".into(), "".into(), file_allowed, get_file_perms)
        .add_ipc_share()
        .auth_provider(NTLMAuthProvider::new(vec![
            User::new("tejasmehta", "password"),
            User::new("tejas2", "password"),
        ], false))
        .listener_address("127.0.0.1:50122").await?;
    let server = builder.build()?;
    println!("here");
    server.start().await
}

#[cfg(not(feature = "async"))]
fn main() -> anyhow::Result<()> {
    let share = SMBShare::disk("someshare".into(), file_allowed, get_file_perms);
    let builder = SMBServerBuilder::<_, TcpListener>::default()
        .anonymous_access(true)
        .unencrypted_access(true)
        .add_share("test", share)
        .listener_address("127.0.0.1:50122")?;
    let mut server = builder.build()?;
    println!("here");
    server.start()
}

fn file_allowed(test: &String) -> bool {
    true
}

fn get_file_perms(test: &String) -> SMBAccessMask {
    SMBAccessMask::Directory(SMBDirectoryAccessMask::GENERIC_ALL)
}