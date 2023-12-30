use std::marker::PhantomData;

use uuid::Uuid;

use error::SMBError;

pub mod error;

pub mod nt_status;

pub type SMBParseResult<I, O, E = SMBError> = Result<(I, O), E>;
pub type SMBResult<O, E = SMBError> = Result<O, E>;

pub trait SMBByteSize {
    fn smb_byte_size(&self) -> usize;
}

pub trait SMBFromBytes: SMBByteSize {
    fn smb_from_bytes(input: &[u8]) -> SMBParseResult<&[u8], Self> where Self: Sized;
}

pub trait SMBToBytes: SMBByteSize {
    fn smb_to_bytes(&self) -> Vec<u8>;
}

pub trait SMBVecByteSize {
    fn smb_byte_size_vec(&self, align: usize, start: usize) -> usize;
}

impl<T: SMBByteSize> SMBVecByteSize for Vec<T> {
    fn smb_byte_size_vec(&self, align: usize, start: usize) -> usize {
        let align = std::cmp::max(align, 1);
        self.iter().fold(start, |prev, x| {
            if align > 1 {
                // println!("Start position for item at {prev} with align {align}");
            }
            let size = x.smb_byte_size();
            let aligned_start = if prev % align == 0 {
                prev
            } else {
                prev + (align - prev % align)
            };
            if align > 1 {
                // println!("adj Start position for item at {aligned_start} with align {align} and size {size}");
            }
            aligned_start + size
        }) - start
    }
}

impl<T: SMBFromBytes> SMBFromBytes for PhantomData<T> {
    fn smb_from_bytes(input: &[u8]) -> SMBParseResult<&[u8], Self> where Self: Sized {
        let (remaining, _) = T::smb_from_bytes(input)?;
        Ok((remaining, PhantomData))
    }
}

impl<T: SMBToBytes> SMBToBytes for PhantomData<T> {
    fn smb_to_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

impl<T> SMBByteSize for PhantomData<T> {
    fn smb_byte_size(&self) -> usize {
        0
    }
}

impl SMBVecFromBytes for String {
    fn smb_from_bytes_vec(input: &[u8], count: usize) -> SMBParseResult<&[u8], Self> where Self: Sized {
        let (remaining, vec) = <Vec<u8>>::smb_from_bytes_vec(input, count)?;
        let str = String::from_utf8(vec)
            .map_err(|_e| SMBError::parse_error("Invalid byte slice"))?;
        Ok((remaining, str))
    }
}

impl SMBVecByteSize for String {
    fn smb_byte_size_vec(&self, align: usize, _: usize) -> usize {
        self.as_bytes().len() * align
    }
}

pub trait SMBVecFromBytes {
    fn smb_from_bytes_vec(input: &[u8], count: usize) -> SMBParseResult<&[u8], Self> where Self: Sized;
}

pub trait SMBEnumFromBytes {
    fn smb_enum_from_bytes(input: &[u8], discriminator: u64) -> SMBParseResult<&[u8], Self> where Self: Sized;
}

impl<T: SMBFromBytes> SMBVecFromBytes for Vec<T> {
    fn smb_from_bytes_vec(input: &[u8], count: usize) -> SMBParseResult<&[u8], Self> where Self: Sized {
        let mut remaining = input;
        let mut done_cnt = 0;
        let mut msg_vec = Vec::<T>::new();
        while done_cnt < count {
            let (r, val) = T::smb_from_bytes(remaining)?;
            msg_vec.push(val);
            remaining = r;
            done_cnt += 1;
        }
        Ok((remaining, msg_vec))
    }
}

impl SMBFromBytes for Uuid {
    fn smb_from_bytes(input: &[u8]) -> SMBParseResult<&[u8], Self> where Self: Sized {
        if 16 > input.len() {
            return Err(SMBError::payload_too_small(16usize, input.len()))
        }
        let uuid = Uuid::from_slice(&input[0..16])
            .map_err(|_e| SMBError::parse_error("Invalid byte slice"))?;
        let remaining = &input[uuid.smb_byte_size()..];
        Ok((remaining, uuid))
    }
}

impl SMBToBytes for Uuid {
    fn smb_to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl SMBByteSize for Uuid {
    fn smb_byte_size(&self) -> usize {
        self.as_bytes().len()
    }
}

macro_rules! impl_parse_fixed_slice {
    ($size: expr, $input: expr) => {{
        if $size as usize > $input.len() {
            return Err(SMBError::payload_too_small($size as usize, $input.len()));
        }
        let res = <[u8; $size]>::try_from(&$input[0..$size])
            .map_err(|_e| SMBError::parse_error("Invalid byte slice"))?;
        Ok((&$input[$size..], res))
    }}
}

macro_rules! impl_smb_byte_size_for_slice {(
    $($N:literal)*
) => (
    $(
        impl SMBByteSize for [u8; $N] {
            fn smb_byte_size(&self) -> usize {
                $N
            }
        }
    )*
)}

macro_rules! impl_smb_from_bytes_for_slice {(
    $($N:literal)*
) => (
    $(
        impl SMBFromBytes for [u8; $N] {
            fn smb_from_bytes(input: &[u8]) -> SMBParseResult<&[u8], Self> {
                impl_parse_fixed_slice!($N, input)
            }
        }
    )*
)}

macro_rules! impl_smb_to_bytes_for_slice {(
    $($N:literal)*
) => (
    $(
        impl SMBToBytes for [u8; $N] {
            fn smb_to_bytes(&self) -> Vec<u8>{
                self.to_vec()
            }
        }
    )*
)}

macro_rules! impl_smb_byte_size_unsigned_type {(
    $($t:ty)*
) => (
    $(
        impl SMBByteSize for $t {
            fn smb_byte_size(&self) -> usize {
                std::mem::size_of_val(self)
            }
        }
    )*
)}

macro_rules! impl_smb_from_bytes_unsigned_type {(
    $($t:ty)*
) => (
    $(
        impl SMBFromBytes for $t {
            fn smb_from_bytes(input: &[u8]) -> SMBParseResult<&[u8], Self> {
                const T_SIZE: usize = std::mem::size_of::<$t>();
                let value = impl_parse_fixed_slice!(T_SIZE, input)?;
                Ok((value.0, <$t>::from_le_bytes(value.1)))
            }
        }
    )*
)}

macro_rules! impl_smb_to_bytes_unsigned_type {(
    $($t:ty)*
) => (
    $(
        impl SMBToBytes for $t {
            fn smb_to_bytes(&self) -> Vec<u8> {
                self.to_le_bytes().to_vec()
            }
        }
    )*
)}

impl_smb_byte_size_for_slice! {
    00 1 2 3 4 5 6 7 8 9
    10 11 12 13 14 15 16
    17 18 19 20 21 22 23 24
    25 26 27 28 29 30 31 32
}

impl_smb_from_bytes_for_slice! {
    00 1 2 3 4 5 6 7 8 9
    10 11 12 13 14 15 16
    17 18 19 20 21 22 23 24
    25 26 27 28 29 30 31 32
}

impl_smb_to_bytes_for_slice! {
    00 1 2 3 4 5 6 7 8 9
    10 11 12 13 14 15 16
    17 18 19 20 21 22 23 24
    25 26 27 28 29 30 31 32
}

impl_smb_byte_size_unsigned_type! {
    u8 u16 u32 u64 u128
}

impl_smb_from_bytes_unsigned_type! {
    u8 u16 u32 u64 u128
}

impl_smb_to_bytes_unsigned_type! {
    u8 u16 u32 u64 u128
}