# AGENTS.md — smb-derive

> **Code is the source of truth.** If anything here conflicts with actual code, trust the code and update this file.

## Crate Role

Procedural macro crate that generates `smb_core` trait implementations for SMB2/3 wire-format types. This is a `proc-macro = true` crate — it runs at compile time and produces code, not runtime artifacts.

## Key Files

| File | Purpose |
|---|---|
| `src/lib.rs` | Four public derive macros + `derive_impl_creator` dispatch |
| `src/attrs.rs` | Attribute parsing (darling-based) for `smb_*` field annotations |
| `src/field.rs` | `SMBFieldType` enum — one variant per attribute kind |
| `src/field_mapping.rs` | Maps struct fields / enum variants to `SMBFieldMapping` |
| `src/smb_from_bytes.rs` | Code generation for `SMBFromBytes` |
| `src/smb_to_bytes.rs` | Code generation for `SMBToBytes` |
| `src/smb_byte_size.rs` | Code generation for `SMBByteSize` |
| `src/smb_enum_from_bytes.rs` | Code generation for `SMBEnumFromBytes` |

## How It Works

1. `derive_impl_creator` receives a `DeriveInput` and detects whether the input is a struct, numeric enum (`#[repr(uN)]`), or discriminated enum.
2. It builds a `Vec<SMBFieldMapping>` describing each field's wire-format layout.
3. The appropriate `CreatorFn` backend (`FromBytesCreator`, `ToBytesCreator`, `ByteSizeCreator`, `EnumFromBytesCreator`) generates the trait impl from the mapping.

## Adding a New Field Attribute

1. Define the attribute struct in `src/attrs.rs` using `darling::FromAttributes`.
2. Add a variant to `SMBFieldType` in `src/field.rs`.
3. Update `get_struct_field_mapping` in `src/field_mapping.rs` to recognize the new attribute.
4. Implement code generation for the new attribute in each of the four `src/smb_*.rs` backends.
5. Add tests in `tests/macro-test.rs`.

## Testing

- `tests/macro-test.rs` — compile-time + runtime tests for the derive macros.
- The `smb` crate's `tests/message.rs` provides end-to-end serialization round-trip coverage.

## Keeping This File Current

When adding new attributes, changing code generation logic, or modifying the field mapping pipeline, update this file as part of the same change.
