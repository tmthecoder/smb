use nom::bytes::complete::take;
use nom::combinator::map;
use nom::IResult;
use nom::number::complete::{le_u16, le_u64};
use nom::sequence::tuple;
use serde::{Serialize, Deserialize};
use crate::byte_helper::{bytes_to_u16, bytes_to_u64, u16_to_bytes, u64_to_bytes};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SMBExtra {
    pid_high: u16,
    signature: u64
}

impl SMBExtra {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Self> {
        map(tuple((le_u16, le_u64, take(2_usize))), |(pid_high, signature, _)| Self {
            pid_high,
            signature
        })(bytes)
    }
}

impl SMBExtra {
    pub fn as_bytes(&self) -> Vec<u8> {
        [
            &u16_to_bytes(self.pid_high)[0..],
            &u64_to_bytes(self.signature)[0..]
        ].concat()
    }
}