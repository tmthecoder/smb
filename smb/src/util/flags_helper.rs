macro_rules! impl_smb_for_bytes_for_bitflag {(
    $($t:ty)*
) => (
    $(
        impl ::smb_core::SMBFromBytes for $t {
            fn smb_byte_size(&self) -> usize {
                std::mem::size_of_val(&self.bits())
            }

            fn parse_smb_payload(input: &[u8]) -> ::smb_core::SMBResult<&[u8], Self, ::smb_core::error::SMBError> {
                const SIZE: usize = std::mem::size_of::<<$t as bitflags::BitFlags>::Bits>();
                if input.len() < SIZE {
                    return Err(::smb_core::error::SMBError::ParseError("Byte slice too small"));
                }
                let bits = <<$t as bitflags::BitFlags>::Bits>::from_le_bytes(
                    <[u8; SIZE]>::parse_smb_payload(&input[0..SIZE])?.1
                );
                let flags = Self::from_bits_truncate(bits);
                Ok((&input[SIZE..], flags))
            }
        }
    )*
)}

pub(crate) use impl_smb_for_bytes_for_bitflag;
