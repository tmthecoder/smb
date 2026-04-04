# smb (smb_reader)

The main crate in the workspace — implements SMB2/3 protocol types, an async server, network transport, authentication (NTLM via SPNEGO), and cryptographic operations.

Built following the [MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962) specification.

## Modules

| Module | Description |
|---|---|
| `protocol` | Wire-format types for SMB2/3 headers, command bodies, and message framing |
| `server` | Async SMB server — connection, session, tree-connect, open, and lease management |
| `socket` | TCP listener and message stream abstractions |
| `util` | Authentication (NTLM/SPNEGO), cryptographic primitives, byte helpers |

### `protocol`

- `header/` — SMB2 packet header (sync/async), command codes, flags, status
- `body/` — Request/response structures for all SMB2 commands: Negotiate, Session Setup, Tree Connect, Create, Read, Write, Lock, Flush, Close, Query Info, Set Info, Query Directory, Change Notify, Echo, Cancel, Oplock Break, IOCTL, Tree Disconnect, Logoff
- `message.rs` — Message wrapper with serialization and cryptographic signing

### `server`

- `client.rs` — SMB client representation
- `connection.rs` — Connection state and lifecycle
- `session.rs` — User session management
- `tree_connect.rs` — Share connection state
- `open.rs` — File/directory open handles
- `lease.rs` — Oplock/lease management
- `channel.rs` — Multi-channel support
- `share/` — Filesystem and IPC share abstractions
- `message_handler.rs` — Command dispatch and response generation
- `request.rs` — Request representation
- `preauth_session.rs` — Pre-authentication session state
- `safe_locked_getter.rs` — Helper for locked access patterns

### `util`

- `auth/auth_context.rs` — `AuthContext` and `AuthProvider` traits
- `auth/user.rs` — User representation with credentials
- `auth/ntlm/` — Full NTLM authentication flow (Negotiate, Challenge, Authenticate)
- `auth/spnego/` — SPNEGO/DER token wrapping
- `crypto/` — DES, NTLMv1 extended, NTLMv2, SMB2 signing/encryption keys, SP800-108 KDF

## Binary

The `spin_server_up` binary starts a development SMB server:

```sh
# Requires features: server, anyhow
cargo run -p smb_reader --features server,anyhow

# Custom port via environment variable (default: 50122)
SMB_PORT=4450 cargo run -p smb_reader --features server,anyhow
```

## Feature Flags

| Feature | Effect |
|---|---|
| `server` | Enables async server (implies `async`) |
| `async` | Enables `tokio`, `tokio-stream`, `tokio-util` |
| `tracing` | Opt-in distributed tracing + `tracing-subscriber` |
| `logging` | Tracing + `log` crate compatibility bridge |
| `anyhow` | Required for the `spin_server_up` binary |

## Tests

Unit tests are co-located in source files. Integration tests live in `tests/`:

| Test file | What it covers |
|---|---|
| `tests/message.rs` | Message serialization/deserialization round-trips |
| `tests/macro.rs` | Procedural macro functionality |
| `tests/smbclient.rs` | End-to-end tests using the system `smbclient` binary (requires `--ignored`) |
