macro_rules! impl_smb_for_bytes_for_bitflag {(
    $($t:ty)*
) => (
    $(
        impl SMBFromBytes for $t {
            fn smb_byte_size() -> usize {
                std::mem::size_of::<<$t as bitflags::BitFlags>::Bits>()
            }

            fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> {
                const SIZE: usize = std::mem::size_of::<<$t as bitflags::BitFlags>::Bits>();
                if input.len() < SIZE {
                    return Err(SMBError::ParseError("Byte slice too small".into()));
                }
                let bits = <<$t as bitflags::BitFlags>::Bits>::from_le_bytes(
                    <[u8; SIZE]>::parse_smb_message(&input[0..SIZE])?.1
                );
                let flags = Self::from_bits_truncate(bits);
                Ok((&input[SIZE..], flags))
            }
        }
    )*
)}

pub(crate) use impl_smb_for_bytes_for_bitflag;
