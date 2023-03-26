use error::SMBError;

pub mod error;

pub type SMBResult<I, O, E> = Result<(I, O), E>;

pub trait SMBFromBytes {
    fn smb_byte_size(&self) -> usize;
    fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> where Self: Sized;
}

pub trait SMBToBytes {
    fn smb_to_bytes();
}

impl<T: SMBFromBytes> SMBFromBytes for Vec<T> {
    fn smb_byte_size(&self) -> usize {
        self.iter().fold(0, |prev, x| prev + x.smb_byte_size())
    }

    fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> where Self: Sized {
        let (remaining, item) = T::parse_smb_message(input)?;
        Ok((remaining, vec![item]))
    }
}

macro_rules! impl_parse_fixed_slice {
    ($size: expr, $input: expr) => {{
        let res = <[u8; $size]>::try_from(&$input[0..$size])
            .map_err(|_e| SMBError::ParseError("Invalid byte slice".into()))?;
        Ok((&$input[$size..], res))
    }}
}

macro_rules! impl_smb_from_bytes_for_slice {(
    $($N:literal)*
) => (
    $(
        impl SMBFromBytes for [u8; $N] {
            fn smb_byte_size(&self) -> usize {
                $N
            }

            fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> {
                impl_parse_fixed_slice!($N, input)
            }
        }
    )*
)}

macro_rules! impl_parse_unsigned_type {(
    $($t:ty)*
) => (
    $(
        impl SMBFromBytes for $t {
            fn smb_byte_size(&self) -> usize {
                std::mem::size_of_val(self)
            }

            fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> {
                const T_SIZE: usize = std::mem::size_of::<$t>();
                let value = impl_parse_fixed_slice!(T_SIZE, input)?;
                Ok((value.0, <$t>::from_le_bytes(value.1)))
            }
        }
    )*
)}

impl_smb_from_bytes_for_slice! {
    00 1 2 3 4 5 6 7 8 9
    10 11 12 13 14 15 16
    17 18 19 20 21 22 23 24
    25 26 27 28 29 30 31 32
}

impl_parse_unsigned_type! {
    u8 u16 u32 u64 u128
}