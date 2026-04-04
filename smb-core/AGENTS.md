# AGENTS.md — smb-core

> **Code is the source of truth.** If anything here conflicts with actual code, trust the code and update this file.

## Crate Role

Foundational crate providing the serialization traits, error types, and logging infrastructure used by the entire workspace. This crate has no dependency on the SMB protocol layer or server — it is purely generic.

## Key Files

| File | Purpose |
|---|---|
| `src/lib.rs` | Core traits + macro-generated impls for primitives |
| `src/error.rs` | `SMBError` enum with all error variants |
| `src/logging.rs` | Feature-gated logging macros wrapping `tracing` |
| `src/nt_status.rs` | NT status code constants |

## Traits

The three primary traits (`SMBByteSize`, `SMBFromBytes`, `SMBToBytes`) form the serialization contract. All SMB wire-format types implement these — typically via the derive macros in `smb-derive`, not by hand.

Additional traits handle vectors (`SMBVecByteSize`, `SMBVecFromBytesCnt`, `SMBVecFromBytesLen`) and discriminated enums (`SMBEnumFromBytes`).

## Adding New Trait Impls

If a new primitive or container type needs to be serializable:
1. Add the impl in `src/lib.rs` (or via the existing macros if it fits the pattern).
2. Ensure all three traits (`SMBByteSize`, `SMBFromBytes`, `SMBToBytes`) are implemented consistently.
3. Add unit tests for the new impl.

## Logging Macros

`logging.rs` uses conditional compilation:
- With `tracing` feature: re-exports `tracing::{trace, debug, info, warn, error, ...}`.
- Without: defines no-op macros that compile away entirely.

Consumers import via `use smb_core::logging::{...};` — never use `tracing` directly.

## Keeping This File Current

When adding new traits, error variants, or changing the logging infrastructure, update this file as part of the same change.
