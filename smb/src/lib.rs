//! # SMB Reader
//!
//! A Rust implementation of the **Server Message Block (SMB) Protocol Versions 2 and 3**
//! as specified in [\[MS-SMB2\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962).
//!
//! This crate provides:
//! - **Protocol layer** ([`protocol`]): Wire-format types for SMB2/3 headers, bodies
//!   (Negotiate, Session Setup, Tree Connect, Create, Read, Write, etc.), and message
//!   framing.
//! - **Server layer** ([`server`]): A generic, async-capable SMB server implementation
//!   including connection, session, tree-connect, and open management.
//! - **Socket layer** ([`socket`]): Abstractions for listening, reading, and writing
//!   SMB messages over TCP (or other transports).
//! - **Utilities** ([`util`]): Authentication helpers (NTLM via SPNEGO), cryptographic
//!   primitives (SP800-108 KDF, HMAC-SHA256, AES-CMAC), and byte-manipulation macros.
//!
//! ## Quick Start
//!
//! ```no_run
//! use smb_reader::server::{SMBServerBuilder, StartSMBServer, DefaultShare};
//! use smb_reader::util::auth::ntlm::NTLMAuthProvider;
//! use smb_reader::util::auth::User;
//! use tokio::net::TcpListener;
//!
//! #[tokio::main]
//! async fn main() -> smb_core::SMBResult<()> {
//!     let server = SMBServerBuilder::<_, TcpListener, NTLMAuthProvider, DefaultShare<NTLMAuthProvider>, _>::default()
//!         .anonymous_access(true)
//!         .auth_provider(NTLMAuthProvider::new(vec![
//!             User::new("user", "pass"),
//!         ], false))
//!         .listener_address("127.0.0.1:445").await?
//!         .build()?;
//!     server.start().await
//! }
//! ```

extern crate core;

use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::ops::{Deref, DerefMut};

use crate::protocol::message::Message;

/// SMB2/3 wire-format protocol types: headers, bodies, and message framing.
pub mod protocol;
/// Utility modules: authentication, cryptography, byte helpers, and flag macros.
pub mod util;
/// SMB server implementation: connection, session, tree-connect, and open management.
pub mod server;
/// Socket abstractions for SMB message transport (TCP listener, read/write streams).
pub mod socket;
mod byte_helper;
