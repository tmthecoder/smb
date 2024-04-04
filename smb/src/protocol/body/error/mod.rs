// #[derive(Debug, SMBFromBytes, SMBToBytes, SMBByteSize)]
// struct SMBErrorResponse {
//     #[smb_skip(start = 0, length = 4)]
//     reserved: PhantomData<Vec<u8>>,
//     #[smb_enum(start(fixed = 8), discriminator(inner(start = 2, num_type = "u8")))]
//     data: SMBErrorData,
// }

// #[derive(Debug, SMBEnumFromBytes, SMBToBytes, SMBByteSize)]
// pub enum SMBErrorData {
//     #[smb_discriminator(value = 0x0)]
//     #[smb_direct(start = 0)]
//     Single(u8),
//     #[smb_discriminator(value = 0x1)]
//     #[smb_direct(start = 0)]
//     Contexts(u8)
// }