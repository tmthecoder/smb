# AGENTS.md — smb (smb_reader)

> **Code is the source of truth.** If anything here conflicts with actual code, trust the code and update this file.

## Crate Role

Main crate implementing the SMB2/3 protocol per [MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962). Contains protocol wire types, async server, networking, auth, and crypto.

## Key Architecture

### Protocol Layer (`src/protocol/`)
- `header/` — Packet header parsing. Sync and async header variants. Command enum, flags (bitflags), and NT status codes.
- `body/` — One sub-module per SMB2 command. `mod.rs` contains the top-level `SMBBody` request/response enums that dispatch by command code.
- `message.rs` — `SMBMessage` wraps header + body. Handles serialization, deserialization, and cryptographic signing.

**Convention:** `mod.rs` in body sub-directories should only hold the request/response types. Flags, enums, and auxiliary info types belong in their own files.

### Server Layer (`src/server/`)
- Generic over `Connection`, `Session`, `Share`, `Open`, `Lease`, and `AuthProvider` via traits.
- `SMBServerBuilder` uses the builder pattern to configure and construct a server.
- `message_handler.rs` dispatches incoming commands to per-command handler logic.

**Lock ordering (critical for deadlock prevention):**
```
server → connection → session → tree_connect → open
```
Always acquire readers before writers. Never invert this ordering.

### Socket Layer (`src/socket/`)
- `listener/` — `SMBListener` trait with sync/async TCP implementations.
- `message_stream/` — `SMBMessageStream` for reading/writing framed SMB messages.

### Utilities (`src/util/`)
- `auth/` — `AuthProvider` trait. NTLM implementation with full Negotiate → Challenge → Authenticate flow. SPNEGO wrapping via DER/ASN.1.
- `crypto/` — SMB2/3 signing keys, encryption keys, NTLMv1/v2 response computation, SP800-108 KDF, DES helpers.
- `flags_helper.rs` — Bitflag manipulation macros.

## Adding a New SMB2 Command

1. Create a sub-directory under `src/protocol/body/` for the command.
2. Define request and response structs with `#[derive(SMBFromBytes, SMBToBytes, SMBByteSize)]`.
3. Add variants to `SMBBody` in `src/protocol/body/mod.rs`.
4. Add handler logic in `src/server/message_handler.rs`.
5. Add `debug!` logging in the handler at minimum.
6. Write unit tests for serialization round-trips and handler behavior.

## Tracing

Import macros at the top of the file:
```rust
use smb_core::logging::{trace, debug, info, warn, error};
```

- `trace!` only for sensitive data (keys, raw buffers, NTLM flags).
- `debug!` for command dispatch, message flow.
- `info!` for lifecycle events.
- Structured fields preferred: `command = ?header.command, mid = header.message_id`.

## Tests

- Unit tests: co-located in source files (`#[cfg(test)]` modules).
- `tests/message.rs` — serialization round-trip tests.
- `tests/smbclient.rs` — integration tests spawning a real server and driving it with `smbclient`. Marked `#[ignore]`.

## Keeping This File Current

When you add new commands, handlers, server features, or change architectural patterns, update this file as part of the same change. Do not let it go stale.
