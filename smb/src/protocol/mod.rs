//! SMB2/3 wire-format protocol definitions.
//!
//! This module contains the complete set of types needed to parse and serialize
//! SMB2/3 messages as defined in [\[MS-SMB2\] Section 2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962).
//!
//! - `header`: SMB2 Packet Header (Sync and Async variants), command codes, flags, and status.
//! - `body`: All SMB2 request/response body structures (Negotiate, Session Setup, Tree Connect, Create, etc.).
//! - `message`: The `SMBMessage` wrapper that pairs a header with a body,
//!   plus serialization, parsing, and cryptographic signing.

pub mod body;
pub mod header;
pub mod message;