# smb-derive

Procedural derive macros for serializing and deserializing SMB2/3 wire-format messages as defined in [MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962).

## Derive Macros

| Macro | Trait Implemented | Purpose |
|---|---|---|
| `SMBFromBytes` | `smb_core::SMBFromBytes` | Parse `&[u8]` into a typed struct/enum |
| `SMBToBytes` | `smb_core::SMBToBytes` | Serialize a struct/enum into `Vec<u8>` |
| `SMBByteSize` | `smb_core::SMBByteSize` | Compute on-wire byte size |
| `SMBEnumFromBytes` | `smb_core::SMBEnumFromBytes` | Parse a discriminated enum from bytes + discriminator |

## Field Attributes

Each struct field must carry exactly one attribute describing its wire-format mapping:

| Attribute | Description |
|---|---|
| `#[smb_direct(start(…))]` | Fixed-size field at a byte offset |
| `#[smb_buffer(offset(…), length(…))]` | Variable-length `Vec<u8>` located by offset/length pair |
| `#[smb_vector(count(…) \| length(…), …)]` | `Vec<T>` with count or byte-length descriptor |
| `#[smb_string(length(…), underlying, …)]` | UTF-8 or UTF-16LE `String` with length descriptor |
| `#[smb_enum(discriminator(…), start(…))]` | Nested discriminated enum |
| `#[smb_skip(start, length)]` | Reserved/padding bytes (`PhantomData`) |
| `#[smb_byte_tag(value)]` | Single-byte sentinel before the struct |
| `#[smb_string_tag(value)]` | Multi-byte string sentinel |

## Offset Specifiers

Attributes accept offset/length/count specifiers:

- `fixed = N` — compile-time constant byte offset
- `"current_pos"` — current parse cursor position
- `inner(start = N, num_type = "u16", subtract = M, min_val = V)` — read value from input at offset N, optionally subtract M (commonly 64 for the SMB2 header size)
- `"null_terminated"` — scan for a null terminator

## Example

```rust
#[derive(SMBFromBytes, SMBToBytes, SMBByteSize)]
#[smb_byte_tag(value = 9)]
pub struct SMBSessionSetupResponse {
    #[smb_direct(start(fixed = 2))]
    session_flags: u16,
    #[smb_buffer(
        offset(inner(start = 4, num_type = "u16", subtract = 64, min_val = 72)),
        length(inner(start = 6, num_type = "u16")),
    )]
    buffer: Vec<u8>,
}
```

## Supported Input Types

- **Structs** — fields annotated with `smb_*` attributes
- **`#[repr(uN)]` enums** — numeric enums read as their repr type and converted via `TryFrom`
- **Discriminated enums** — variants selected by an external discriminator, each with `#[smb_discriminator(value = …)]`
