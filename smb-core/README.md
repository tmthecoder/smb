# smb-core

Core traits, error types, and feature-gated logging macros shared across the SMB workspace.

## Traits

| Trait | Purpose |
|---|---|
| `SMBByteSize` | Compute the on-wire byte size of a type |
| `SMBFromBytes` | Parse a `&[u8]` slice into a typed value |
| `SMBToBytes` | Serialize a value into `Vec<u8>` (little-endian wire format) |
| `SMBVecByteSize` | Byte size for `Vec<T>` with alignment |
| `SMBVecFromBytesCnt` | Parse a `Vec<T>` given an element count |
| `SMBVecFromBytesLen` | Parse a `Vec<T>` given a total byte length |
| `SMBEnumFromBytes` | Parse a discriminated enum given an external discriminator value |

Built-in implementations are provided for `u8`–`u128`, `[u8; 0]`–`[u8; 32]`, `Uuid`, `String`, and `PhantomData<T>`.

## Error Types

`SMBError` in `error.rs` covers:
- `SMBParseError` — malformed input during deserialization
- `SMBCryptoError` — cryptographic operation failures
- `SMBPreconditionFailedError` — unmet preconditions
- `SMBIOError` — I/O errors
- `SMBResponseError` — response generation failures
- `SMBPayloadTooSmallError` — input buffer too short
- `SMBServerError` — server-level errors

## Logging

`logging.rs` provides feature-gated macros (`trace!`, `debug!`, `info!`, `warn!`, `error!`, spans) that delegate to the `tracing` crate when the `tracing` feature is enabled, or compile to no-ops when disabled.

## Feature Flags

| Feature | Effect |
|---|---|
| `tracing` | Enables `tracing` crate dependency and re-exports logging macros |
| `logging` | Enables `tracing/log` compatibility (bridges `tracing` events to the `log` crate) |

## NT Status Codes

`nt_status.rs` defines NT status code constants used in SMB2 response headers, following the [MS-ERREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/) specification.
