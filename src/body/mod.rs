use crate::header::Header;

mod body;
mod negotiate;

pub type SMBBody = body::SMBBody;

pub type LegacySMBBody = body::LegacySMBBody;

pub trait Body<S: Header> {
    type Item;

    fn from_bytes_and_header<'a>(bytes: &'a [u8], header: &S) -> (Self::Item, &'a [u8]);
}