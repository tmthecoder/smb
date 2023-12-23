macro_rules! impl_smb_byte_size_for_bitflag {(
    $($t:ty)*
) => (
    $(
        impl ::smb_core::SMBByteSize for $t {
           fn smb_byte_size(&self) -> usize {
               std::mem::size_of_val(&self.bits())
           }
        }
    )*
)}
macro_rules! impl_smb_from_bytes_for_bitflag {(
    $($t:ty)*
) => (
    $(
        impl ::smb_core::SMBFromBytes for $t {
            fn smb_from_bytes(input: &[u8]) -> ::smb_core::SMBParseResult<&[u8], Self, ::smb_core::error::SMBError> {
                const SIZE: usize = std::mem::size_of::<<$t as bitflags::BitFlags>::Bits>();
                if input.len() < SIZE {
                    return Err(::smb_core::error::SMBError::parse_error("Byte slice too small"));
                }
                let bits = <<$t as bitflags::BitFlags>::Bits>::from_le_bytes(
                    <[u8; SIZE]>::smb_from_bytes(&input[0..SIZE])?.1
                );
                let flags = Self::from_bits_truncate(bits);
                Ok((&input[SIZE..], flags))
            }
        }
    )*
)}

macro_rules! impl_smb_to_bytes_for_bitflag {(
    $($t:ty)*
) => (
    $(
        impl ::smb_core::SMBToBytes for $t {
            fn smb_to_bytes(&self) -> Vec<u8> {
                self.bits().to_le_bytes().to_vec()
            }
        }
    )*
)}

pub(crate) use impl_smb_byte_size_for_bitflag;
pub(crate) use impl_smb_from_bytes_for_bitflag;
pub(crate) use impl_smb_to_bytes_for_bitflag;