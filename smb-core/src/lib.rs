use std::marker::PhantomData;

use uuid::Uuid;

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

impl<T: SMBFromBytes> SMBFromBytes for PhantomData<T> {
    fn smb_byte_size(&self) -> usize {
        0
    }

    fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> where Self: Sized {
        let (remaining, _) = T::parse_smb_message(input)?;
        Ok((remaining, PhantomData))
    }
}

impl SMBFromBytes for String {
    fn smb_byte_size(&self) -> usize {
        self.as_bytes().len()
    }

    fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> where Self: Sized {
        let (remaining, vec) = <Vec<u8>>::parse_smb_message(input)?;
        let str = String::from_utf8(vec)
            .map_err(|_e| SMBError::ParseError("Invalid byte slice".into()))?;
        Ok((remaining, str))
    }
}

pub trait SMBVecFromBytes {
    fn parse_smb_message_vec(input: &[u8], count: usize) -> SMBResult<&[u8], Self, SMBError> where Self: Sized;
}

impl<T: SMBFromBytes> SMBVecFromBytes for Vec<T> {
    fn parse_smb_message_vec(input: &[u8], count: usize) -> SMBResult<&[u8], Self, SMBError> where Self: Sized {
        let mut remaining = input;
        let mut done_cnt = 0;
        let mut msg_vec = Vec::<T>::new();
        while done_cnt < count {
            let (r, val) = T::parse_smb_message(remaining)?;
            msg_vec.push(val);
            remaining = r;
            done_cnt += 1;
        }
        Ok((remaining, msg_vec))
    }
}

impl SMBVecFromBytes for String {
    fn parse_smb_message_vec(input: &[u8], count: usize) -> SMBResult<&[u8], Self, SMBError> where Self: Sized {
        let (remaining, vec) = <Vec<u16>>::parse_smb_message_vec(input, count / 2)?;
        let string = String::from_utf16(&vec)
            .map_err(|_e| SMBError::ParseError("Invalid string"))?;
        Ok((remaining, string))
    }
}

// impl<T> SMBFromBytes for T where T: Into<String> + TryFrom<String> + Clone {
//     fn smb_byte_size(&self) -> usize {
//         Into::into(self.clone()).as_bytes().len()
//     }
//
//     fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> where Self: Sized {
//         let string = String::from_utf8(input.into())
//             .map_err(|_e| SMBError::ParseError("Invalid slice".into()))?;
//         let value = T::try_from(string)
//             .map_err(|_e| SMBError::ParseError("Invalid string".into()));
//         Ok((&input[string.len()..], ))
//     }
// }

impl SMBFromBytes for Uuid {
    fn smb_byte_size(&self) -> usize {
        16
    }

    fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> where Self: Sized {
        let uuid = Uuid::from_slice(&input[0..16])
            .map_err(|_e| SMBError::ParseError("Invalid byte slice".into()))?;
        let remaining = &input[uuid.smb_byte_size()..];
        Ok((remaining, uuid))
    }
}

// impl<'a, T> SMBFromBytes for T where T: From<&'a [u8]> {
//     fn smb_byte_size(&self) -> usize {
//         self.into().len()
//     }
//
//     fn parse_smb_message(input: &[u8]) -> SMBResult<&[u8], Self, SMBError> where Self: Sized {
//         let val = T::from(input);
//         let remaining = &input[val.smb_byte_size()..];
//         Ok((remaining, val))
//     }
// }

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