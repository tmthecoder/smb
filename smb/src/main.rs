use smb_reader::server::SMBServerBuilder;

const NTLM_ID: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
const SPNEGO_ID: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

fn main() -> anyhow::Result<()> {
    let builder = SMBServerBuilder::default()
        .anonymous_access(true)
        .unencrypted_access(true)
        .listener_address("127.0.0.1:50122")?;
    let mut server = builder.build()?;
    server.start()
}