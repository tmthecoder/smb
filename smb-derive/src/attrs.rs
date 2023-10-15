use darling::{FromAttributes, FromDeriveInput, FromField, FromMeta};
use proc_macro2::{Ident, TokenStream, TokenTree};
use quote::{format_ident, quote, quote_spanned};
use syn::{Attribute, DeriveInput, Meta, Path, Token, Type, TypePath};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;

#[derive(Debug, FromDeriveInput, FromAttributes, FromField, Default, PartialEq, Eq)]
#[darling(attributes(smb_direct))]
pub struct Direct {
    #[darling(map = From::< isize >::from)]
    pub start: DirectStart,
    #[darling(default)]
    pub order: usize
}

#[derive(Debug, Default, PartialEq, Eq, FromMeta)]
pub enum DirectStart {
    Location(usize),
    #[default] CurrentPos,
}

impl From<isize> for DirectStart {
    fn from(value: isize) -> Self {
        if value < 0 {
            DirectStart::CurrentPos
        } else {
            DirectStart::Location(value as usize)
        }
    }
}

impl Direct {
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T, name: &Ident, ty: &Type) -> TokenStream {
        let start = if let DirectStart::Location(s) = self.start {
            quote! { #s }
        } else {
            quote! { current_pos }
        };
        quote_spanned! { spanned.span() =>
            let (remaining, #name) = <#ty>::smb_from_bytes(&input[#start..])?;
            current_pos = ::smb_core::SMBByteSize::smb_byte_size(&#name) + #start;
        }
    }

    pub(crate) fn smb_to_bytes<T: Spanned>(&self, spanned: &T, token: &TokenTree) -> TokenStream {
        let start = if let DirectStart::Location(s) = self.start {
            quote! { #s }
        } else {
            quote! { current_pos }
        };
        quote_spanned! { spanned.span()=>
            let size = ::smb_core::SMBByteSize::smb_byte_size(&#token);
            let bytes = ::smb_core::SMBToBytes::smb_to_bytes(&#token);
            item[#start..(#start + size)].copy_from_slice(&bytes);
            current_pos = #start + size;
        }
    }

    pub(crate) fn attr_byte_size(&self) -> usize { 0 }
}

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
            Type::Path(TypePath {
                qself: None,
                path: Path::from(Ident::new(ty, spanned.span())),
            })
        } else {
            Type::Path(TypePath {
                qself: None,
                path: Path::from(Ident::new("usize", spanned.span())),
            })
        }
    }

    fn smb_from_bytes<T: Spanned>(&self, name: &str, spanned: &T) -> TokenStream {
        let start = self.start;
        let subtract = self.subtract;
        let name = format_ident!("{}", name);
        let ty = self.get_type(spanned);
        let chunk = if self.num_type != "direct" {
            quote! {
                let (remaining, #name) = <#ty>::smb_from_bytes(&input[#start..])?;
            }
        } else {
            quote! { let #name = current_pos; }
        };
        quote_spanned! {spanned.span()=>
            #chunk
            let #name = #name - #subtract as #ty;
        }
    }

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

#[derive(Debug, FromDeriveInput, FromAttributes, FromField, PartialEq, Eq)]
#[darling(attributes(smb_buffer))]
pub struct Buffer {
    #[darling(default)]
    pub order: usize,
    pub offset: DirectInner,
    pub length: DirectInner,
}

impl Buffer {
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T, name: &Ident) -> TokenStream {
        let offset = self.offset.smb_from_bytes("offset", spanned);
        let length = self.length.smb_from_bytes("length", spanned);

        quote_spanned! { spanned.span() =>
            #offset
            #length
            let buf_end = offset as usize + length as usize;
            let #name = input[(offset as usize)..(offset as usize + length as usize)].to_vec();
            let remaining = &input[buf_end..];
        }
    }

    pub(crate) fn smb_to_bytes<T: Spanned>(&self, spanned: &T, token: &TokenTree) -> TokenStream {
        let offset_info = self.offset.smb_to_bytes("offset", spanned, None);
        let length_info = self.length.smb_to_bytes("length", spanned, Some(quote! {
            bytes.len()
        }));

        quote_spanned! {spanned.span()=>
            let bytes = &#token;

            #offset_info
            #length_info

            let length = bytes.len();
            item[current_pos..(current_pos + length)].copy_from_slice(&bytes);
            current_pos += length;
        }
    }

    pub(crate) fn attr_byte_size(&self) -> usize { 0 }
}

#[derive(Debug, FromDeriveInput, FromAttributes, FromField, PartialEq, Eq)]
#[darling(attributes(smb_vector))]
pub struct Vector {
    pub order: usize,
    pub count: DirectInner,
    pub offset: Option<DirectInner>,
    #[darling(default)]
    pub align: usize,
}

impl Vector {
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T, name: &Ident, ty: &Type) -> TokenStream {
        let count = self.count.smb_from_bytes("item_count", spanned);
        let align = self.align;
        let offset = self.offset
            .as_ref()
            .map_or(quote! {
                let item_offset = current_pos;
            }, |offset| offset.smb_from_bytes("item_offset", spanned));
        quote_spanned! { spanned.span() =>
            #count
            if #align > 0 && current_pos % #align != 0 {
                current_pos += 8 - (current_pos % #align);
            }
            #offset
            let item_offset = item_offset as usize;
            let (remaining, #name): (&[u8], #ty) = ::smb_core::SMBVecFromBytes::smb_from_bytes_vec(&input[item_offset..], item_count as usize)?;
            current_pos = item_offset + ::smb_core::SMBVecByteSize::smb_byte_size_vec(&#name, #align, item_offset);
        }
    }

    pub(crate) fn smb_to_bytes<T: Spanned>(&self, spanned: &T, token: &TokenTree) -> TokenStream {
        let count_info = self.count.smb_to_bytes("item_count", spanned, Some(quote! {
          #token.len()
        }));
        let offset_info = self.offset
            .as_ref()
            .map_or(quote! {}, |offset| offset.smb_to_bytes("item_offset", spanned, None));
        let align = self.align;

        quote_spanned! { spanned.span()=>
            #count_info
            let get_aligned_pos = |align: usize, current_pos: usize| {
                if align > 0 && current_pos % align != 0 {
                    current_pos + (8 - current_pos % align)
                } else {
                    current_pos
                }
            };
            current_pos = get_aligned_pos(#align, current_pos);
            #offset_info
            for entry in #token.iter() {
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
        }
    }

    pub(crate) fn attr_byte_size(&self) -> usize { 0 }
}

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
            while input[current_pos] != #start_byte {
                current_pos += 1;
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
                if input[(pos)..].starts_with(#start_val.as_bytes()) {
                    current_pos = pos;
                    tagged = true;
                    next_pos = pos;
                    break;
                }
                current_pos += 1;
            }
            if (!tagged) {
                return Err(::smb_core::error::SMBError::ParseError("struct did not have the valid starting tag"));
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

#[derive(Debug)]
pub struct Repr {
    pub ident: Ident,
}

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

