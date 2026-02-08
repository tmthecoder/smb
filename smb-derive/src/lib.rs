//! # smb-derive
//!
//! Procedural derive macros for serializing and deserializing SMB2/3 protocol
//! wire-format messages as defined in
//! [\[MS-SMB2\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962).
//!
//! ## Overview
//!
//! SMB2/3 messages are packed binary structures with fields at fixed byte offsets,
//! variable-length buffers located via offset/length pairs, vectors with count or
//! length descriptors, UTF-16LE strings, and discriminated unions. These macros
//! generate implementations of the [`smb_core`] traits:
//!
//! | Derive macro | Trait implemented | Purpose |
//! |---|---|---|
//! | [`SMBFromBytes`] | `smb_core::SMBFromBytes` | Parse a `&[u8]` slice into a typed struct/enum |
//! | [`SMBToBytes`] | `smb_core::SMBToBytes` | Serialize a struct/enum into `Vec<u8>` |
//! | [`SMBByteSize`] | `smb_core::SMBByteSize` | Compute the on-wire byte size |
//! | [`SMBEnumFromBytes`] | `smb_core::SMBEnumFromBytes` | Parse a discriminated enum from bytes + discriminator |
//!
//! ## Field Attributes
//!
//! Each struct field must carry exactly one of the following attributes to
//! describe how it maps onto the wire format:
//!
//! | Attribute | Description |
//! |---|---|
//! | `#[smb_direct(start(…))]` | Fixed-size field read/written at a byte offset |
//! | `#[smb_buffer(offset(…), length(…))]` | Variable-length `Vec<u8>` located by an offset/length pair |
//! | `#[smb_vector(count(…) \| length(…), …)]` | `Vec<T>` located by a count or byte-length descriptor |
//! | `#[smb_string(length(…), underlying, …)]` | UTF-8 or UTF-16LE `String` with a length descriptor |
//! | `#[smb_enum(discriminator(…), start(…))]` | Nested discriminated enum field |
//! | `#[smb_skip(start, length)]` | Reserved/padding bytes (mapped to `PhantomData`) |
//! | `#[smb_byte_tag(value)]` | Single-byte sentinel that must appear before the struct |
//! | `#[smb_string_tag(value)]` | Multi-byte string sentinel (e.g. `"SMB"`) |
//!
//! ## Offset Specifiers (`AttributeInfo`)
//!
//! Many attributes accept an offset/length/count specifier that can be:
//!
//! - `fixed = N` — a compile-time constant byte offset.
//! - `"current_pos"` — the current parse cursor position.
//! - `inner(start = N, num_type = "u16", subtract = M, min_val = V)` — read
//!   the value from the input at byte offset `N` as the given numeric type,
//!   then subtract `M` (commonly the SMB2 header size, 64).
//! - `"null_terminated"` — scan for a null terminator of the given width.
//!
//! ## Example
//!
//! ```rust,ignore
//! #[derive(SMBFromBytes, SMBToBytes, SMBByteSize)]
//! #[smb_byte_tag(value = 9)]
//! pub struct SMBSessionSetupResponse {
//!     #[smb_direct(start(fixed = 2))]
//!     session_flags: u16,
//!     #[smb_buffer(
//!         offset(inner(start = 4, num_type = "u16", subtract = 64, min_val = 72)),
//!         length(inner(start = 6, num_type = "u16")),
//!     )]
//!     buffer: Vec<u8>,
//! }
//! ```

#![feature(let_chains)]
extern crate proc_macro;

use proc_macro::TokenStream;
use std::fmt::{Debug, Display, Formatter};

use darling::FromAttributes;
use proc_macro2::Ident;
use quote::quote_spanned;
use syn::{Data, DeriveInput, parse_macro_input};
use syn::spanned::Spanned;

use crate::field::SMBFieldType;
use crate::field_mapping::{enum_repr_type, get_desc_enum_mapping, get_num_enum_mapping, get_struct_field_mapping, SMBFieldMapping};
use crate::smb_byte_size::ByteSizeCreator;
use crate::smb_enum_from_bytes::EnumFromBytesCreator;
use crate::smb_from_bytes::FromBytesCreator;
use crate::smb_to_bytes::ToBytesCreator;

mod attrs;
mod field_mapping;
mod field;
mod smb_from_bytes;
mod smb_byte_size;
mod smb_to_bytes;
mod smb_enum_from_bytes;


/// Derive macro that generates an `impl smb_core::SMBFromBytes` for a struct or
/// `#[repr(uN)]` enum.
///
/// For structs, each field must be annotated with one of the `smb_*` field
/// attributes so the macro knows where in the byte slice to read it.
///
/// For `#[repr(u8)]` / `#[repr(u16)]` / … enums ("numeric enums"), the raw
/// integer is read from offset 0 and converted via `TryFrom`.
///
/// # Panics (compile-time)
///
/// Emits `compile_error!` if the input type is unsupported or a field is
/// missing its annotation.
#[proc_macro_derive(SMBFromBytes, attributes(smb_direct, smb_buffer, smb_vector, smb_string, smb_enum, smb_skip, smb_byte_tag, smb_string_tag))]
pub fn smb_from_bytes(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);

    let parse_token = derive_impl_creator(input, FromBytesCreator {});

    parse_token.into()
}

/// Derive macro that generates an `impl smb_core::SMBEnumFromBytes` for a
/// discriminated enum — i.e. a Rust `enum` whose variants carry associated data
/// and are selected by an external discriminator value.
///
/// Each variant must have:
/// - `#[smb_discriminator(value = 0x…)]` — one or more discriminator values
///   that select this variant.
/// - Exactly one `smb_*` field attribute on the variant itself describing how
///   to parse the payload.
///
/// The generated `smb_enum_from_bytes(input, discriminator)` matches the
/// discriminator and delegates to the per-variant parser.
#[proc_macro_derive(SMBEnumFromBytes, attributes(smb_direct, smb_buffer, smb_vector, smb_string, smb_enum, smb_skip, smb_byte_tag, smb_string_tag, smb_discriminator))]
pub fn smb_enum_from_bytes(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);

    let parse_token = derive_impl_creator(input, EnumFromBytesCreator {});

    parse_token.into()
}

/// Derive macro that generates an `impl smb_core::SMBToBytes` for a struct or
/// enum.
///
/// Allocates a `Vec<u8>` of the correct size (via `SMBByteSize`) and writes
/// each field into its wire-format position. Field ordering and placement is
/// controlled by the same `smb_*` attributes used for parsing.
#[proc_macro_derive(SMBToBytes, attributes(smb_direct, smb_buffer, smb_vector, smb_string, smb_enum, smb_skip, smb_byte_tag, smb_string_tag))]
pub fn smb_to_bytes(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);

    let parse_token = derive_impl_creator(input, ToBytesCreator {});

    parse_token.into()
}

/// Derive macro that generates an `impl smb_core::SMBByteSize` for a struct or
/// enum.
///
/// Computes the total on-wire byte size by summing fixed-field sizes, skip
/// regions, tag bytes, and the dynamic sizes of any buffer/vector/string
/// fields.
#[proc_macro_derive(SMBByteSize, attributes(smb_direct, smb_buffer, smb_vector, smb_string, smb_enum, smb_skip, smb_byte_tag, smb_string_tag))]
pub fn smb_byte_size(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);

    let parse_token = derive_impl_creator(input, ByteSizeCreator {});

    parse_token.into()
}


/// Central dispatch that maps a [`DeriveInput`] (struct or enum) into the
/// appropriate [`SMBFieldMapping`] and then delegates to the supplied
/// [`CreatorFn`] to produce the final trait implementation.
///
/// - **Structs** are mapped via [`get_struct_field_mapping`].
/// - **`#[repr(uN)]` enums** (numeric enums) are mapped via [`get_num_enum_mapping`].
/// - **Discriminated enums** (no `repr`) are mapped via [`get_desc_enum_mapping`].
fn derive_impl_creator(input: DeriveInput, creator: impl CreatorFn) -> proc_macro2::TokenStream {
    let name = &input.ident;

    let invalid_token: proc_macro2::TokenStream = quote_spanned! {
        input.span() => compile_error!("Invalid or unsupported type")
    };

    let parent_attrs = parent_attrs(&input);

    let parse_token = match &input.data {
        Data::Struct(structure) => {
            let mapping = get_struct_field_mapping(&structure.fields, parent_attrs, vec![], None)
                .map(|r| vec![r]);
            creator.call(mapping, name)
                .unwrap_or_else(|e| match e {
                    SMBDeriveError::TypeError(f) => quote_spanned! {f.span()=>::std::compile_error!("Invalid field for SMB message parsing")},
                    _ => invalid_token
                })
        },
        Data::Enum(enum_info) => {
            match enum_repr_type(&input.attrs) {
                Ok(repr) => {
                    let mapping = get_num_enum_mapping(&input, parent_attrs, repr)
                        .map(|r| vec![r]);
                    creator.call(mapping, name)
                        .unwrap_or_else(|_e| quote_spanned! {input.span()=>
                            ::std::compile_error!("Invalid enum for SMB message parsing")
                        })
                },
                Err(_) => {
                    let mapping = get_desc_enum_mapping(enum_info);
                    creator.call(mapping, name)
                        .unwrap_or_else(|e| match e {
                            SMBDeriveError::TypeError(f) => quote_spanned! {f.span()=>::std::compile_error!("Invalid field for SMB message parsing")},
                            _ => invalid_token
                        })
                }
            }
        },
        _ => invalid_token
    };

    parse_token
}


/// Extracts any struct-level / enum-level `smb_*` attributes (e.g.
/// `#[smb_byte_tag(…)]`, `#[smb_string_tag(…)]`) from the top-level
/// `DeriveInput` and returns them as a sorted list of [`SMBFieldType`]s.
fn parent_attrs(input: &DeriveInput) -> Vec<SMBFieldType> {
    input.attrs.iter().filter_map(|attr| {
        SMBFieldType::from_attributes(&[attr.clone()]).ok()
    }).collect()
}

/// Trait object interface for the four code-generation backends.
///
/// Each backend ([`FromBytesCreator`], [`ToBytesCreator`], [`ByteSizeCreator`],
/// [`EnumFromBytesCreator`]) implements this trait so that
/// [`derive_impl_creator`] can dispatch generically.
trait CreatorFn {
    fn call<T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq + Debug>(self, mapping: Result<Vec<SMBFieldMapping<T, U>>, SMBDeriveError<U>>, name: &Ident) -> Result<proc_macro2::TokenStream, SMBDeriveError<U>>;
}

/// Errors that can occur during derive-macro expansion.
#[derive(Debug)]
enum SMBDeriveError<T: Spanned + Debug> {
    TypeError(T),
    MissingField,
    InvalidType,
}

impl<T: Spanned + Debug> Display for SMBDeriveError<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TypeError(span) => write!(f, "No type annotation for spannable ${:?} (must be buffer or direct)", span),
            Self::MissingField => write!(f, "Needed attribute for field missing"),
            Self::InvalidType => write!(f, "Unsupported or invalid type"),
        }
    }
}

impl<T: Spanned + Debug> std::error::Error for SMBDeriveError<T> {}