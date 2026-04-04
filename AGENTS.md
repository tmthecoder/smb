# AGENTS.md

> **Code is the source of truth.** This file provides guidance for AI agents working on this project.
> If anything here conflicts with the actual code, trust the code — then update this file to fix the discrepancy.
> When adding new behavior or changing existing behavior, update the relevant AGENTS.md file(s) as part of the same change.

## Project Overview

This is a Rust implementation of the [MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962) protocol (SMB versions 2 and 3). The MS-SMB2 spec is the authoritative reference for all protocol behavior. Use the [Rust Book](https://doc.rust-lang.org/book/) and `cargo clippy` as the primary references for idiomatic Rust.

## Workspace Structure

| Crate | Path | Purpose |
|---|---|---|
| `smb_reader` | `smb/` | Main crate — protocol types, async server, socket layer, auth, crypto |
| `smb-core` | `smb-core/` | Core traits (`SMBFromBytes`, `SMBToBytes`, `SMBByteSize`), errors, logging macros |
| `smb-derive` | `smb-derive/` | Procedural derive macros for wire-format serialization |

Each crate has its own `AGENTS.md` with crate-specific guidance.

## Development Rules

### Branch Discipline
- **Never commit to `main` directly.** Always cut a feature branch before starting work.
- Open a PR with a clear, accurate description when the work is complete.

### Test Coverage
- All code changes must be accompanied by tests.
- When editing existing files, review and add tests where coverage is missing.
- Never leave changed code untested if tests can reasonably be written.

### Running Tests
```sh
cargo test --lib --features server              # Unit tests
cargo test --test message --features server,anyhow  # Message round-trips
cargo test --test smbclient --features server,anyhow -- --ignored  # smbclient integration
```

### Code Style
- Follow Rust Book conventions for error handling, enums/pattern matching, and traits.
- Run `cargo clippy --workspace --features server -- -D warnings` before committing.
- `mod.rs` should only contain request/response types for its directory. Auxiliary types (flags, enums, info types) go in their own files.

### Concurrency / Lock Ordering
When acquiring locks, follow strict outer-to-inner ordering to prevent deadlocks:

```
server → connection → session → tree_connect → open
```

- Always acquire readers before writers.
- Never invert this ordering.

### Tracing & Logging
Tracing is feature-gated and fully opt-in. Macros live in `smb_core::logging`.

**Import style** — always at the top of the file:
```rust
use smb_core::logging::{trace, debug, info, warn, error};
```

**Log levels:**
| Level | Use for |
|---|---|
| `error!` | Unrecoverable failures, states that should never happen |
| `warn!` | Recoverable issues, degraded behavior |
| `info!` | Significant lifecycle events (server start, session setup complete) |
| `debug!` | Operational detail (command dispatch, message send/receive) |
| `trace!` | Verbose/sensitive data — **never in production** (keys, raw buffers, NTLM flags) |

- All sensitive data (keys, crypto material, auth tokens, raw buffers) **must** use `trace!` only.
- Use structured fields (`command = ?header.command`) rather than format strings.
- Every new handler or protocol message type should include at least `debug!` logging.

### Feature Flags
| Feature | Effect |
|---|---|
| `server` | Async server (implies `async` → tokio) |
| `tracing` | Opt-in tracing via `tracing` crate |
| `logging` | Tracing + `log` crate compatibility |

These are **independent** — `server` does NOT imply `tracing`.

Build with tracing: `--features "server,tracing,anyhow"`

## Keeping AGENTS.md Current

- **Code is always the source of truth.** Never assume AGENTS.md is complete or up-to-date without checking the code.
- When you find a discrepancy between AGENTS.md and the code, update AGENTS.md.
- When you add new behavior, patterns, or conventions, update the relevant AGENTS.md as part of the same PR.
- Do not let AGENTS.md files go stale — treat them as living documentation.
