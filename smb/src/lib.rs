#![feature(tuple_trait)]
#![feature(return_position_impl_trait_in_trait)]
extern crate core;

use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::ops::{Deref, DerefMut};

use crate::protocol::message::Message;

pub mod protocol;
pub mod util;
pub mod server;
pub mod socket;
mod byte_helper;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
