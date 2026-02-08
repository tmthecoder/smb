use std::default::Default;

use darling::{FromAttributes, FromDeriveInput, FromField, FromMeta};
use darling::ast::NestedMeta;
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote, quote_spanned};
use syn::{Attribute, DeriveInput, Expr, Lit, Meta, Path, Token, Type, TypePath};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;

/// Construct a [`syn::Type`] from a primitive type name string (e.g. `"u16"`,
/// `"usize"`), using the span of `spanned` for error reporting.
fn get_type<T: Spanned>(underlying: &str, spanned: &T) -> Type {
    Type::Path(TypePath {
        qself: None,
        path: Path::from(Ident::new(underlying, spanned.span())),
    })
}

/// Describes a value that is read from the wire at a fixed byte offset
/// (`start`) as a specific numeric type (`num_type`), then optionally adjusted
/// by subtracting `subtract` (commonly the 64-byte SMB2 header size) and
/// clamped to a minimum of `min_val`.
///
/// This is the `inner(start = N, num_type = "u16", subtract = M, min_val = V)`
/// variant of [`AttributeInfo`].
#[derive(Debug, PartialEq, Eq, FromMeta)]
pub struct DirectInner {
    pub start: usize,
    pub num_type: String,
    #[darling(default)]
    pub subtract: usize,
    #[darling(default)]
    pub min_val: usize,
}

impl DirectInner {
    fn get_type<T: Spanned>(&self, spanned: &T) -> Type {
        let ty = &self.num_type;
        if self.num_type != "direct" {
            get_type(ty, spanned)
        } else {
            get_type("usize", spanned)
        }
    }

    /// Generate a token stream that reads a numeric value from `input[start..]`,
    /// converts it to the configured type, and subtracts the `subtract` offset.
    /// When `num_type == "direct"`, the value is taken from `current_pos` instead.
    fn smb_from_bytes<T: Spanned>(&self, name: &str, spanned: &T) -> TokenStream {
        let start = self.start;
        let subtract = self.subtract;
        let name = format_ident!("{}", name);
        let ty = self.get_type(spanned);
        let chunk = if self.num_type != "direct" {
            quote! {
                if #start >= input.len() {
                    return Err(::smb_core::error::SMBError::payload_too_small(#start as usize, input.len()));
                }
                let (remaining, #name): (&[u8], #ty) = ::smb_core::SMBFromBytes::smb_from_bytes(&input[#start..])?;
                // println!("value of item: {:?}", #name);
            }
        } else {
            quote! { let #name = current_pos; }
        };
        quote_spanned! {spanned.span()=>
            #chunk
            let #name = ::std::cmp::max(#name, #subtract as #ty) - #subtract as #ty;
        }
    }

    /// Generate a token stream that serializes a value back into the output
    /// buffer at `start`, adding back the `subtract` offset and clamping to
    /// `min_val`.
    fn smb_to_bytes<T: Spanned>(&self, name: &str, spanned: &T, name_val: Option<TokenStream>) -> TokenStream {
        let start = self.start;
        let subtract = self.subtract;
        let name = format_ident!("{}", name);
        let ty = &self.get_type(spanned);
        let name_start = format_ident!("{}_start", name);
        let name_len = format_ident!("{}_len", name);
        let name_add = format_ident!("{}_add", name);
        let name_bytes = format_ident!("{}_bytes", name);
        let min_val = self.min_val;
        let end = if self.num_type == "direct" {
            quote! {0}
        } else {
            quote! { ::smb_core::SMBByteSize::smb_byte_size(&(0 as #ty)) }
        };

        let new_current_pos = if name_val.is_some() {
            quote! {
                current_pos = current_pos;
            }
        } else {
            quote! {
                current_pos = (#name - #name_add);
            }
        };

        let name_val = name_val.unwrap_or(quote! {
            #name_add + current_pos
        });

        quote_spanned! {spanned.span()=>
            let #name_start = #start;
            let #name_add = #subtract;
            let #name_len = #end;
            let #name = ::std::cmp::max(#name_val, #min_val);
            let #name_bytes = ::smb_core::SMBToBytes::smb_to_bytes(&(#name as #ty));
            item[#name_start..(#name_start + #name_len)].copy_from_slice(&#name_bytes);
            #new_current_pos
            current_pos = ::std::cmp::max(current_pos, #name_start + #name_len);
        }
    }
}

/// Describes how to locate a byte offset, length, or count value for an SMB
/// field. This is the central "offset specifier" type used by all field
/// attributes.
///
/// # Variants
///
/// - **`Fixed(N)`** — compile-time constant offset.
/// - **`Inner(DirectInner)`** — read from the wire at a given position.
/// - **`CurrentPos`** — use the current parse cursor (`current_pos`).
/// - **`NullTerminated(type_name)`** — scan forward for a null terminator of
///   the given numeric width (e.g. `"u8"` or `"u16"`).
#[derive(Debug, Default, PartialEq, Eq)]
pub enum AttributeInfo {
    Fixed(usize),
    Inner(DirectInner),
    #[default] CurrentPos,
    NullTerminated(String),
}

impl FromMeta for AttributeInfo {
    fn from_list(items: &[NestedMeta]) -> darling::Result<Self> {
        for item in items {
            if let NestedMeta::Meta(Meta::NameValue(meta)) = item {
                if meta.path.is_ident("fixed") {
                    if let Expr::Lit(lit) = &meta.value {
                        if let Lit::Int(int) = &lit.lit {
                            return Ok(AttributeInfo::Fixed(int.base10_parse::<usize>()?))
                        }
                    }
                }
            } else if let NestedMeta::Meta(Meta::List(list)) = item {
                if list.path.is_ident("inner") {
                    return Ok(AttributeInfo::Inner(DirectInner::from_nested_meta(item)?))
                } else if list.path.is_ident("null_terminated") {
                    return Ok(AttributeInfo::NullTerminated(String::from_nested_meta(item)?))
                }
            }
        }
        Err(darling::Error::missing_field("fixed | current_pos | inner | null_terminated"))
    }

    fn from_string(value: &str) -> darling::Result<Self> {
        match value.to_lowercase().trim().replace([' ', '_'], "").as_str() {
            "currentpos" => Ok(AttributeInfo::CurrentPos),
            "nullterminated" => Ok(AttributeInfo::NullTerminated("u8".into())),
            _ => Err(darling::Error::missing_field("fixed | current_pos | inner | null_terminated"))
        }
    }
}

impl AttributeInfo {
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T, name: &str) -> TokenStream {
        let name_ident = format_ident!("{}", name);
        match self {
            Self::CurrentPos => quote! { let #name_ident = current_pos; },
            Self::Fixed(start) => quote! { let #name_ident = #start; },
            Self::Inner(inner) => inner.smb_from_bytes(name, spanned),
            Self::NullTerminated(num_ty) => {
                let ty = get_type(num_ty, spanned);
                quote! {
                    if item_offset >= input.len() {
                        return Err(::smb_core::error::SMBError::payload_too_small(item_offset as usize, input.len()));
                    }
                    let mut val = &input[item_offset..];
                    let size = ::smb_core::SMBByteSize::smb_byte_size(&(0 as #ty));
                    let mut count = 0;
                    while let Ok((rest, num)) = <#ty as ::smb_core::SMBFromBytes>::smb_from_bytes(val) {
                        val = rest;
                        count += size;
                        if num == 0 {
                            break;
                        }
                    }
                    let #name_ident = count;
                }
            }
        }
    }

    pub(crate) fn smb_to_bytes<T: Spanned>(&self, spanned: &T, name: &str, name_val: Option<TokenStream>) -> TokenStream {
        let name_ident = format_ident!("{}", name);
        match self {
            Self::CurrentPos => quote! { let #name_ident = current_pos; },
            Self::Fixed(start) => quote! { let #name_ident = #start; },
            Self::Inner(inner) => inner.smb_to_bytes(name, spanned, name_val),
            Self::NullTerminated(_) => quote! {},
        }
    }

    pub(crate) fn get_pos(&self) -> usize {
        match self {
            Self::CurrentPos | Self::NullTerminated(_) => 0,
            Self::Fixed(pos) => *pos,
            Self::Inner(inner) => inner.start
        }
    }

    pub(crate) fn get_min_val(&self) -> usize {
        match self {
            Self::Inner(inner) => inner.min_val.saturating_sub(inner.subtract),
            _ => 0,
        }
    }
    pub(crate) fn get_type<S: Spanned>(&self, spanned: &S) -> Option<Type> {
        match self {
            Self::Inner(inner) => Some(inner.get_type(spanned)),
            _ => None,
        }
    }
}

impl From<isize> for AttributeInfo {
    fn from(value: isize) -> Self {
        if value < 0 {
            AttributeInfo::CurrentPos
        } else {
            AttributeInfo::Fixed(value as usize)
        }
    }
}

/// `#[smb_direct(start(…))]` — a fixed-size field at a known byte offset.
///
/// Used for primitive types (`u8`, `u16`, `u32`, `u64`, `u128`), fixed-size
/// arrays (`[u8; N]`), and any type implementing `SMBFromBytes` / `SMBToBytes`.
///
/// The `start` specifier tells the macro where in the input slice the field
/// begins. An optional `order` controls serialization ordering when multiple
/// fields share the same logical position.
#[derive(Debug, FromDeriveInput, FromAttributes, FromField, Default, PartialEq, Eq)]
#[darling(attributes(smb_direct))]
pub struct Direct {
    pub start: AttributeInfo,
    #[darling(default)]
    pub order: usize,
}

impl Direct {
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T, name: &Ident, ty: &Type) -> TokenStream {
        let start = self.start.smb_from_bytes(spanned, "item_start");
        quote_spanned! { spanned.span() =>
            #start
            if item_start as usize >= input.len() as usize {
                return Err(::smb_core::error::SMBError::payload_too_small(item_start as usize, input.len() as usize));
            }
            let (remaining, #name): (&[u8], #ty) = ::smb_core::SMBFromBytes::smb_from_bytes(&input[(item_start as usize)..])?;
            current_pos = ::smb_core::SMBByteSize::smb_byte_size(&#name) + item_start as usize;
        }
    }

    pub(crate) fn smb_to_bytes<T: Spanned>(&self, spanned: &T, token: &TokenStream) -> TokenStream {
        let start = self.start.smb_to_bytes(spanned, "item_start", None);
        quote_spanned! { spanned.span()=>
            #start
            let size = ::smb_core::SMBByteSize::smb_byte_size(#token);
            let bytes = ::smb_core::SMBToBytes::smb_to_bytes(#token);
            item[(item_start as usize)..(item_start as usize + size)].copy_from_slice(&bytes);
            current_pos = item_start as usize + size;
        }
    }

    pub(crate) fn attr_byte_size(&self) -> usize { 0 }
}

/// `#[smb_buffer(offset(…), length(…))]` — a variable-length byte buffer.
///
/// Maps to `Vec<u8>`. The `offset` specifier locates the buffer start and the
/// `length` specifier gives the byte count. Both are typically `inner(…)`
/// references that read offset/length values from the wire.
///
/// This corresponds to the common SMB2 pattern of
/// `BufferOffset (2 bytes) + BufferLength (2 bytes)` descriptor pairs.
#[derive(Debug, FromDeriveInput, FromAttributes, FromField, PartialEq, Eq)]
#[darling(attributes(smb_buffer))]
pub struct Buffer {
    #[darling(default)]
    pub order: usize,
    #[darling(default)]
    pub offset: AttributeInfo,
    pub length: AttributeInfo,
}

impl Buffer {
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T, name: &Ident) -> TokenStream {
        let offset = self.offset.smb_from_bytes(spanned, "offset");
        let length = self.length.smb_from_bytes(spanned, "length");

        quote_spanned! { spanned.span() =>
            #offset
            #length
            let buf_end = offset as usize + length as usize;
            if buf_end > input.len() as usize {
                return Err(::smb_core::error::SMBError::payload_too_small(buf_end as usize, input.len() as usize));
            }
            let #name = input[(offset as usize)..buf_end].to_vec();
            let remaining = &input[buf_end..];
        }
    }

    pub(crate) fn smb_to_bytes<T: Spanned>(&self, spanned: &T, token: &TokenStream) -> TokenStream {
        let offset_info = self.offset.smb_to_bytes(spanned, "offset", None);
        let length_info = self.length.smb_to_bytes(spanned, "length", Some(quote! {
            bytes.len()
        }));

        quote_spanned! {spanned.span()=>
            let bytes = #token;

            #offset_info
            #length_info

            let length = bytes.len();
            item[current_pos..(current_pos + length)].copy_from_slice(&bytes);
            current_pos += length;
        }
    }

    pub(crate) fn attr_byte_size(&self) -> usize { 0 }
}

/// `#[smb_vector(count(…) | length(…), offset(…), align = N)]` — a vector of
/// typed elements.
///
/// Maps to `Vec<T>` where `T: SMBFromBytes`. Exactly one of `count` (element
/// count) or `length` (total byte length) must be specified. An optional
/// `offset` locates the start of the vector data, and `align` specifies
/// per-element alignment padding (e.g. 8 for 8-byte aligned create contexts).
///
/// Validation ensures that exactly one of `count`/`length` is provided.
#[derive(Debug, FromDeriveInput, FromAttributes, FromField, PartialEq, Eq)]
#[darling(attributes(smb_vector))]
#[darling(and_then = "Vector::validate_attrs")]
pub struct Vector {
    pub order: usize,
    #[darling(default)]
    pub count: AttributeInfo,
    #[darling(default)]
    pub length: AttributeInfo,
    #[darling(default)]
    pub offset: AttributeInfo,
    #[darling(default)]
    pub align: usize,
}

impl Vector {
    pub(crate) fn validate_attrs(self) -> darling::Result<Self> {
        let default = AttributeInfo::default();
        if self.count == default && self.length == default {
            return Err(darling::Error::custom("count or length must be specified for smb_vector types"));
        } else if self.count != default && self.length != default {
            return Err(darling::Error::custom("only one of count or length can be specified for smb_vector types"));
        }
        Ok(self)
    }
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T, name: &Ident, ty: &Type) -> TokenStream {
        let vec_count_or_len = if self.count == AttributeInfo::default() {
            self.length.smb_from_bytes(spanned, "item_length")
        } else {
            self.count.smb_from_bytes(spanned, "item_count")
        };
        // println!("Count: {}", vec_count_or_len);
        let align = self.align;
        let offset = self.offset.smb_from_bytes(spanned, "item_offset");
        let parser = if self.count == AttributeInfo::default() {
            quote! {
                let (remaining, #name): (&[u8], #ty) = ::smb_core::SMBVecFromBytesLen::smb_from_bytes_vec_len(&input[item_offset..], #align as usize, item_length as usize)?;
            }
        } else {
            quote! {
                let (remaining, #name): (&[u8], #ty) = ::smb_core::SMBVecFromBytesCnt::smb_from_bytes_vec_cnt(&input[item_offset..], #align as usize, item_count as usize)?;
            }
        };
        let _name_str = name.to_string();
        quote_spanned! { spanned.span() =>
            // println!("cnt/len parse for {:?}", #_name_str);
            #vec_count_or_len
            if #align > 0 && current_pos % #align != 0 {
                current_pos += #align - (current_pos % #align);
            }
            #offset
            let item_offset = item_offset as usize;
            if item_offset >= input.len() {
                return Err(::smb_core::error::SMBError::payload_too_small(item_offset as usize, input.len()));
            }
            #parser
            // let (remaining, #name): (&[u8], #ty) = ::smb_core::SMBVecFromBytesCnt::smb_from_bytes_vec_cnt(&input[item_offset..], #align as usize, item_count as usize)?;
            current_pos = item_offset + ::smb_core::SMBVecByteSize::smb_byte_size_vec(&#name, #align, item_offset);
        }
    }

    pub(crate) fn smb_to_bytes<T: Spanned>(&self, spanned: &T, raw_token: &TokenStream) -> TokenStream {
        let count_info = if self.count == AttributeInfo::default() {
            quote! {}
        } else {
            self.count.smb_to_bytes(spanned, "item_count", Some(quote! {
              #raw_token.len()
            }))
        };
        let len_info = if self.length == AttributeInfo::default() {
            quote! {}
        } else {
            self.length.smb_to_bytes(spanned, "item_length", Some(quote! {
                byte_size
            }))
        };
        let offset_info = self.offset.smb_to_bytes(spanned, "item_offset", None);
        let align = self.align;

        quote_spanned! { spanned.span()=>
            #count_info
            let get_aligned_pos = |align: usize, current_pos: usize| {
                if align > 0 && current_pos % align != 0 {
                    current_pos + (align - current_pos % align)
                } else {
                    current_pos
                }
            };
            #offset_info
            current_pos = get_aligned_pos(#align, current_pos);
            let start_pos = current_pos;
            for entry in #raw_token.iter() {
                let item_bytes = ::smb_core::SMBToBytes::smb_to_bytes(entry);
                // if (#align > 0) {
                //     println!("item with align {} initial starting pos {}, item bytes: {:?}", #align, current_pos, item_bytes);
                // }
                current_pos = get_aligned_pos(#align, current_pos);
                item[current_pos..(current_pos + item_bytes.len())].copy_from_slice(&item_bytes);
                // if (#align > 0) {
                //     println!("adding item with align {} at starting pos {}, item bytes: {:?}", #align, current_pos, item_bytes);
                // }
                current_pos += item_bytes.len();
            }
            let byte_size = current_pos - start_pos;
            #len_info
        }
    }

    pub(crate) fn attr_byte_size(&self) -> usize { 0 }
}

/// `#[smb_string(length(…), underlying = "u16", …)]` — a UTF-8 or UTF-16LE
/// string field.
///
/// Maps to `String`. The `underlying` parameter specifies the character
/// encoding width: `"u8"` for UTF-8, `"u16"` for UTF-16LE (the SMB2 default).
/// The `length` specifier gives the byte length of the encoded string on the
/// wire. An optional `start`/offset locates the string data.
///
/// For UTF-16LE strings, the byte length is divided by 2 to get the element
/// count before parsing.
#[derive(Debug, FromDeriveInput, FromAttributes, FromField, Eq, PartialEq)]
#[darling(attributes(smb_string))]
#[darling(and_then = "SMBString::match_attr_info")]
pub struct SMBString {
    pub order: usize,
    #[darling(default)]
    pub start: AttributeInfo,
    pub length: AttributeInfo,
    pub underlying: String,
}

impl SMBString {
    fn match_attr_info(self) -> darling::Result<Self> {
        let Self {
            order,
            start,
            mut length,
            underlying
        } = self;
        if let AttributeInfo::NullTerminated(_) = &length {
            length = AttributeInfo::NullTerminated(underlying.clone())
        }
        Ok(Self {
            order,
            start,
            length,
            underlying,
        })
    }
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T, name: &Ident) -> TokenStream {
        let length = self.length.smb_from_bytes(spanned, "item_count");
        let start = self.start.smb_from_bytes(spanned, "item_offset");
        let vec_name = format_ident!("{}_vec", name);
        let string_parser = match self.underlying.as_str() {
            "u8" => quote! {
                let #name = String::from_utf8(#vec_name).map_err(|e| ::smb_core::error::SMBError::parse_error("Invalid UTF-8 string"))?;
            },
            "u16" => quote! {
                let #name = String::from_utf16(&#vec_name).map_err(|e| ::smb_core::error::SMBError::parse_error("Invalid UTF-16 string"))?;
            },
            _ => quote! {}
        };

        let num_type = get_type(&self.underlying, spanned);

        quote_spanned! { spanned.span() =>
            #start
            let item_offset = item_offset as usize;
            #length
            if item_offset >= input.len() {
                return Err(::smb_core::error::SMBError::payload_too_small(item_offset as usize, input.len()));
            }
            let (remaining, #vec_name): (&[u8], Vec<#num_type>) = ::smb_core::SMBVecFromBytesCnt::smb_from_bytes_vec_cnt(&input[item_offset..], 0, (item_count/2) as usize)?;
            #string_parser
            current_pos = item_offset + ::smb_core::SMBVecByteSize::smb_byte_size_vec(&#name, 0, item_offset);
        }
    }

    pub(crate) fn smb_to_bytes<T: Spanned>(&self, spanned: &T, raw_token: &TokenStream) -> TokenStream {
        let (count_expr, string_to_bytes) = match self.underlying.as_str() {
            "u8" => (
                quote! { #raw_token.len() },
                quote! { let token_vec = #raw_token.as_bytes().to_vec(); },
            ),
            "u16" => (
                quote! { #raw_token.encode_utf16().count() * 2 },
                quote! { let token_vec: Vec<u16> = #raw_token.encode_utf16().collect(); },
            ),
            _ => (quote! { 0 }, quote! {}),
        };
        let count_info = self.length.smb_to_bytes(spanned, "item_count", Some(count_expr));
        let offset_info = self.start.smb_to_bytes(spanned, "item_offset", None);
        quote_spanned! { spanned.span()=>
            #count_info
            #offset_info
            #string_to_bytes
            for entry in token_vec {
                let item_bytes = ::smb_core::SMBToBytes::smb_to_bytes(&entry);
                // if (#align > 0) {
                //     println!("item with align {} initial starting pos {}, item bytes: {:?}", #align, current_pos, item_bytes);
                // }
                // current_pos = get_aligned_pos(#align, current_pos);
                item[current_pos..(current_pos + item_bytes.len())].copy_from_slice(&item_bytes);
                // if (#align > 0) {
                //     println!("adding item with align {} at starting pos {}, item bytes: {:?}", #align, current_pos, item_bytes);
                // }
                current_pos += item_bytes.len();
            }
        }
    }

    pub(crate) fn attr_byte_size(&self) -> usize { 0 }
}

/// `#[smb_discriminator(value = 0x…)]` — marks a discriminated enum variant
/// with one or more discriminator values.
///
/// Used on variants of enums deriving [`SMBEnumFromBytes`]. Multiple `value`
/// entries are OR'd with the optional `flag` to produce the final set of
/// discriminator values that select this variant.
#[derive(Debug, FromDeriveInput, FromAttributes, FromField, Eq, PartialEq)]
#[darling(attributes(smb_discriminator))]
pub struct Discriminator {
    #[darling(multiple, rename = "value")]
    pub values: Vec<u64>,
    #[darling(default)]
    pub flag: u64,
}

/// Bitwise/shift modifiers applied to a discriminator value before matching.
///
/// Used in `#[smb_enum(… modifier(and = 0x10), modifier(right_shift = 4))]`
/// to extract sub-fields from a packed discriminator (e.g. extracting the
/// access mask type from a combined flags field).
#[derive(Debug, Default, PartialEq, Eq, FromMeta)]
pub enum SMBAttributeModifier {
    #[default] None,
    And(u64),
    Or(u64),
    RightShift(u64),
    LeftShift(u64),
}

impl SMBAttributeModifier {
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T, name: &Ident, name_ty: &Type) -> TokenStream {
        match self {
            SMBAttributeModifier::None => quote! {},
            SMBAttributeModifier::And(value) => quote_spanned! {spanned.span()=>
                let #name = #name & (#value as #name_ty);
            },
            SMBAttributeModifier::Or(value) => quote_spanned! {spanned.span()=>
                let #name = #name | (#value as #name_ty);
            },
            SMBAttributeModifier::RightShift(value) => quote_spanned! {spanned.span()=>
                let #name = #name >> (#value as #name_ty);
            },
            SMBAttributeModifier::LeftShift(value) => quote_spanned! {spanned.span()=>
                let #name = #name << (#value as #name_ty);
            },
        }
    }
}

/// `#[smb_enum(discriminator(…), start(…))]` — a nested discriminated enum
/// field.
///
/// The `discriminator` specifier tells the macro where to read the
/// discriminator value from the wire, and `start` tells it where the enum
/// payload begins. Optional `modifier` entries apply bitwise operations to the
/// discriminator before dispatch.
///
/// The field type must implement `SMBEnumFromBytes`.
#[derive(Debug, FromDeriveInput, FromAttributes, FromField, Eq, PartialEq)]
#[darling(attributes(smb_enum))]
pub struct SMBEnum {
    pub discriminator: AttributeInfo,
    #[darling(default)]
    pub start: AttributeInfo,
    #[darling(default)]
    pub order: usize,
    #[darling(multiple, default, rename = "modifier")]
    pub modifiers: Vec<SMBAttributeModifier>,
    #[darling(default = "SMBEnum::default_should_write")]
    pub should_write: bool
}

impl SMBEnum {
    pub(crate) fn default_should_write() -> bool {
        true
    }
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T, name: &Ident) -> TokenStream {
        let discriminator_info = self.discriminator.smb_from_bytes(spanned, "item_discriminator");
        let start_info = self.start.smb_from_bytes(spanned, "item_start");
        let discrim_type = match &self.discriminator {
            AttributeInfo::Inner(inner) => get_type(&inner.num_type, spanned),
            _ => get_type("usize", spanned)
        };
        let discrim_ident = format_ident!("item_discriminator");
        let all_modifier_ops: Vec<TokenStream> = self.modifiers.iter()
            .map(|modifier| modifier.smb_from_bytes(spanned, &discrim_ident, &discrim_type))
            .collect();
        let modifier_info = quote_spanned! {spanned.span()=>
            #(#all_modifier_ops)*
        };
        quote! {
            #start_info
            #discriminator_info
            #modifier_info
            if item_start as usize >= input.len() {
                return Err(::smb_core::error::SMBError::payload_too_small(item_start as usize, input.len()));
            }
            let (remaining, #name) = ::smb_core::SMBEnumFromBytes::smb_enum_from_bytes(&input[item_start as usize..], item_discriminator as u64)?;
        }
    }

    pub(crate) fn smb_to_bytes<T: Spanned>(&self, spanned: &T, token: &TokenStream) -> TokenStream {
        let start_info = self.start.smb_to_bytes(spanned, "item_start", None);
        // TODO should we write the discriminator here?
        // let discriminator_info = match self.should_write {
        //     true => self.discriminator.smb_to_bytes(spanned, "discriminator_info", None),
        //     false => quote!{}
        // };
        quote! {
            #start_info
            let size = ::smb_core::SMBByteSize::smb_byte_size(#token);
            let bytes = ::smb_core::SMBToBytes::smb_to_bytes(#token);
            item[(item_start as usize)..(item_start as usize + size)].copy_from_slice(&bytes);
            current_pos = item_start as usize + size;
        }
    }

    pub(crate) fn attr_byte_size(&self) -> usize { 0 }
}

/// `#[smb_byte_tag(value = 0xNN)]` — a single-byte sentinel/tag.
///
/// Applied at the struct level. During parsing, the macro scans forward from
/// `current_pos` until it finds a byte matching `value`. During serialization,
/// the byte is written at `current_pos`.
///
/// Commonly used for the SMB2 StructureSize field (e.g. `value = 64` for the
/// header, `value = 25` for Session Setup Request).
#[derive(Debug, FromDeriveInput, FromAttributes, FromField, Default, Eq, PartialEq)]
#[darling(attributes(smb_byte_tag))]
pub struct ByteTag {
    pub value: u8,
    #[darling(default)]
    pub order: usize,
}

impl ByteTag {
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T) -> TokenStream {
        let start_byte = self.value;
        quote_spanned! {spanned.span()=>
            while current_pos < input.len() && input[current_pos] != #start_byte {
                current_pos += 1;
            }
            if current_pos >= input.len() {
                return Err(::smb_core::error::SMBError::parse_error("byte tag not found in input"));
            }
            let remaining = &input[current_pos..];
        }
    }
    pub(crate) fn smb_to_bytes<T: Spanned>(&self, spanned: &T) -> TokenStream {
        let start_byte = self.value;
        quote_spanned! {spanned.span()=>
            item[current_pos] = #start_byte;
            current_pos += 1;
        }
    }

    pub(crate) fn attr_byte_size(&self) -> usize { 1 }
}

/// `#[smb_string_tag(value = "SMB")]` — a multi-byte string sentinel/tag.
///
/// Applied at the struct level. During parsing, scans forward for the first
/// occurrence of the byte sequence. During serialization, writes the string
/// bytes at `current_pos`.
///
/// Used for the `"SMB"` magic bytes in the SMB2 header (bytes 1-3 after the
/// `0xFE` protocol byte).
#[derive(FromDeriveInput, FromField, FromAttributes, Default, Debug, Eq, PartialEq)]
#[darling(attributes(smb_string_tag))]
pub struct StringTag {
    pub value: String,
    #[darling(default)]
    pub order: usize,
}

impl StringTag {
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T) -> TokenStream {
        let start_val = &self.value;
        quote_spanned! {spanned.span()=>
             let mut tagged = false;
             let mut next_pos = current_pos;
             while let Some(pos) = input[current_pos..].iter().position(|x| *x == #start_val.as_bytes()[0]) {
                let abs_pos = current_pos + pos;
                if input[abs_pos..].starts_with(#start_val.as_bytes()) {
                    current_pos = abs_pos;
                    tagged = true;
                    next_pos = abs_pos;
                    break;
                }
                current_pos = abs_pos + 1;
            }
            if (!tagged) {
                return Err(::smb_core::error::SMBError::parse_error("struct did not have the valid starting tag"));
            }
            let remaining = &input[next_pos..];
        }
    }
    pub(crate) fn smb_to_bytes<T: Spanned>(&self, spanned: &T) -> TokenStream {
        let start_val = &self.value;
        quote_spanned! {spanned.span()=>
            let bytes = #start_val.as_bytes();
            item[current_pos..(current_pos + bytes.len())].copy_from_slice(&bytes);
            current_pos += bytes.len();
        }
    }

    pub(crate) fn attr_byte_size(&self) -> usize { self.value.len() }
}

/// Extracts the `#[repr(uN)]` type from an enum's attributes.
///
/// Used to distinguish numeric enums (which have a `repr`) from discriminated
/// enums (which do not).
#[derive(Debug)]
pub struct Repr {
    pub ident: Ident,
}

/// `#[smb_skip(start = N, length = M)]` — reserved/padding bytes.
///
/// Advances the parse cursor past `length` bytes starting at offset `start`.
/// The field type should be `PhantomData<…>`. An optional `value` provides
/// fixed bytes to write during serialization (e.g. `[0xFF, 0xFE, 0, 0]` for
/// the SMB2 header Reserved field).
#[derive(Debug, FromDeriveInput, FromAttributes, FromField, PartialEq, Eq)]
#[darling(attributes(smb_skip))]
pub struct Skip {
    pub start: usize,
    pub length: usize,
    #[darling(default)]
    pub value: Vec<u8>,
}

impl Skip {
    pub(crate) fn new(start: usize, length: usize) -> Self {
        Self { start, length, value: Vec::new() }
    }
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T, name: &Ident, ty: &Type) -> TokenStream {
        let start = self.start;
        let length = self.length;

        quote_spanned! {spanned.span() =>
            current_pos = #start + #length;
            let remaining = &input[current_pos..];
            let #name: #ty = ::std::marker::PhantomData;
        }
    }
    pub(crate) fn smb_to_bytes<T: Spanned>(&self, spanned: &T) -> TokenStream {
        let start = self.start;
        let length = self.length;
        if self.value.len() == length {
            let value = self.value.clone();
            quote_spanned! {spanned.span()=>
                let value = [#(#value,)*];
                item[#start..(#start + #length)].copy_from_slice(&value);
                current_pos = #start + #length;
            }
        } else {
            quote_spanned! {spanned.span() =>
                current_pos = #start + #length;
            }
        }
    }

    pub(crate) fn attr_byte_size(&self) -> usize { 0 }
}

impl FromDeriveInput for Repr {
    fn from_derive_input(input: &DeriveInput) -> darling::Result<Self> {
        Self::from_attributes(&input.attrs)
    }
}

impl FromAttributes for Repr {
    fn from_attributes(attrs: &[Attribute]) -> darling::Result<Self> {
        for attr in attrs.iter() {
            if attr.path().is_ident("repr") {
                let nested = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
                for meta in nested {
                    if let Meta::Path(p) = meta {
                        if let Some(ident) = p.get_ident() {
                            return Ok(Self {
                                ident: ident.clone()
                            })
                        }
                    }
                }
            }
        }
        Err(darling::Error::custom("Could not derive 'repr' type"))
    }
}

#[cfg(test)]
mod tests {
    use darling::FromAttributes;
    use quote::quote;
    use syn::Attribute;
    use syn::parse::{Parse, ParseStream};

    use crate::attrs::{Repr, Skip};

    struct AttrsTestStruct {
        attrs: Vec<Attribute>,
    }

    impl Parse for AttrsTestStruct {
        fn parse(input: ParseStream) -> syn::Result<Self> {
            Ok(AttrsTestStruct {
                attrs: input.call(Attribute::parse_outer)?,
            })
        }
    }

    #[test]
    fn test_repr_from_attributes() {
        let struct_stream = quote! {
            #[repr(u8)]
            #[derive(Debug)]
        };
        let struct_buffer: AttrsTestStruct = syn::parse2(struct_stream).unwrap();
        assert_eq!(Repr::from_attributes(&struct_buffer.attrs).unwrap().ident.to_string(), "u8");
    }

    #[test]
    fn test_smb_skip() {
        let skip = Skip::new(10, 10);
        // let skip_to_bytes= skip.smb_to_bytes();
    }
}

