# smb

A Rust implementation of the [Server Message Block (SMB) Protocol Versions 2 and 3][ms-smb2],
built from the ground up following the official Microsoft specification.

## Workspace

| Crate | Description |
|---|---|
| [`smb`](./smb) | Protocol types, async server, networking, authentication, and cryptography |
| [`smb-core`](./smb-core) | Core traits (`SMBFromBytes`, `SMBToBytes`, `SMBByteSize`) and error types |
| [`smb-derive`](./smb-derive) | Procedural derive macros for wire-format serialization/deserialization |

## Building

Requires **Rust nightly** (edition 2024).

```sh
# Library check
cargo check --workspace --features server

# Build the server binary
cargo build -p smb_reader --features server,anyhow

# Build with tracing enabled
cargo build -p smb_reader --features server,tracing,anyhow
```

## Running

```sh
# Default port (50122)
cargo run -p smb_reader --features server,anyhow

# Custom port
SMB_PORT=4450 cargo run -p smb_reader --features server,anyhow

# With tracing (default level: info, override with RUST_LOG)
RUST_LOG=debug cargo run -p smb_reader --features server,tracing,anyhow
```

The server listens on `127.0.0.1:<port>` and exposes a filesystem share (`test`) and an IPC share.

## Testing

```sh
# Unit tests
cargo test --lib --features server

# Integration tests (message serialization round-trips)
cargo test --test message --features server,anyhow

# Integration tests with smbclient (requires smbclient installed)
cargo test --test smbclient --features server,anyhow -- --ignored
```

## CI

GitHub Actions runs on every push:

| Workflow | What it does |
|---|---|
| `check.yml` | `cargo check` + `cargo clippy -- -D warnings` |
| `unit-tests.yml` | `cargo test --lib --features server` |
| `integration-tests.yml` | Message round-trip tests + smbclient integration tests |
| `docs.yml` | `cargo doc --workspace --features server --no-deps` |

## Feature Flags

Defined in the `smb` crate:

| Feature | Effect |
|---|---|
| `server` | Enables async server (implies `async`) |
| `async` | Enables tokio runtime |
| `tracing` | Opt-in distributed tracing via the `tracing` crate |
| `logging` | Enables tracing + `log` crate compatibility bridge |
| `anyhow` | Required for the `spin_server_up` binary |

## Specification

This implementation follows the [MS-SMB2][ms-smb2] specification. Related specs:

- [MS-NLMP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/) — NTLM authentication
- [MS-SPNG](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/) — SPNEGO negotiation

[ms-smb2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962
