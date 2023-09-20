use darling::{FromAttributes, FromDeriveInput, FromField, FromMeta};
use proc_macro2::{Ident, TokenTree};
use quote::{format_ident, quote, quote_spanned};
use syn::{Attribute, DeriveInput, Meta, Path, Token, Type, TypePath};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;

#[derive(Debug, FromDeriveInput, FromAttributes, FromField, Default, PartialEq, Eq)]
#[darling(attributes(smb_direct))]
pub struct Direct {
    pub start: usize,
}

impl Direct {
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T, name: &Ident, ty: &Type) -> proc_macro2::TokenStream {
        let start = self.start;
        quote_spanned! { spanned.span() =>
            let (remaining, #name) = <#ty>::smb_from_bytes(&input[#start..])?;
            current_pos = ::smb_core::SMBByteSize::smb_byte_size(&#name) + #start;
        }
    }

    pub(crate) fn smb_to_bytes<T: Spanned>(&self, spanned: &T, token: &TokenTree) -> proc_macro2::TokenStream {
        let start = self.start;
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

    fn smb_from_bytes<T: Spanned>(&self, name: &str, spanned: &T) -> proc_macro2::TokenStream {
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

    fn smb_to_bytes<T: Spanned>(&self, name: &str, spanned: &T) -> proc_macro2::TokenStream {
        let start = self.start;
        let subtract = self.subtract;
        let name = format_ident!("{}", name);
        let ty = &self.get_type(spanned);
        let name_start = format_ident!("{}_start", name);
        let name_len = format_ident!("{}_len", name);
        let name_add = format_ident!("{}_add", name);
        let name_bytes = format_ident!("{}_bytes", name);
        let end = if self.num_type == "direct" {
            quote! {0}
        } else {
            quote! { ::smb_core::SMBByteSize::smb_byte_size(&(0 as #ty)) }
        };

        quote_spanned! {spanned.span()=>
            let #name_start = #start;
            let #name_add = #subtract;
            let #name_len = #end;
            let #name = #name_add + current_pos;
            let #name_bytes = ::smb_core::SMBToBytes::smb_to_bytes(&(#name as #ty));
            item[#name_start..(#name_start + #name_len)].copy_from_slice(&#name_bytes);
        }
    }
}

#[derive(Debug, FromDeriveInput, FromAttributes, FromField, PartialEq, Eq)]
#[darling(attributes(smb_buffer))]
pub struct Buffer {
    pub offset: DirectInner,
    pub length: DirectInner,
}

impl Buffer {
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T, name: &Ident) -> proc_macro2::TokenStream {
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

    pub(crate) fn smb_to_bytes<T: Spanned>(&self, spanned: &T, token: &TokenTree) -> proc_macro2::TokenStream {
        let offset_info = self.offset.smb_to_bytes("offset", spanned);
        let length_info = self.length.smb_to_bytes("length", spanned);


        quote_spanned! {spanned.span()=>
            #offset_info
            #length_info

            let length = ::smb_core::SMBByteSize::smb_byte_size(&#token);
            let bytes = ::smb_core::SMBToBytes::smb_to_bytes(&#token);
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
    #[darling(default)]
    pub align: usize,
}

impl Vector {
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T, name: &Ident, ty: &Type) -> proc_macro2::TokenStream {
        let count = self.count.smb_from_bytes("item_count", spanned);
        let align = self.align;
        quote_spanned! { spanned.span() =>
            #count
            if #align > 0 && current_pos % #align != 0 {
                current_pos += 8 - (current_pos % #align);
            }
            let (remaining, #name): (&[u8], #ty) = ::smb_core::SMBVecFromBytes::smb_from_bytes_vec(&input[current_pos..], item_count as usize)?;
            current_pos += ::smb_core::SMBByteSize::smb_byte_size(&#name);
        }
    }

    pub(crate) fn smb_to_bytes<T: Spanned>(&self, spanned: &T, token: &TokenTree) -> proc_macro2::TokenStream {
        let count_info = self.count.smb_to_bytes("item_count", spanned);
        let align = self.align;

        quote_spanned! { spanned.span()=>
            #count_info
            if #align > 0 && current_pos % #align != 0 {
                current_pos += 8 - (current_pos % #align);
            }
            for entry in #token.iter() {
                let item_bytes = ::smb_core::SMBToBytes::smb_to_bytes(entry);
                item[current_pos..(current_pos + item_bytes.len())].copy_from_slice(&item_bytes);
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
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T) -> proc_macro2::TokenStream {
        let start_byte = self.value.clone();
        quote_spanned! {spanned.span()=>
            while input[current_pos] != #start_byte {
                current_pos += 1;
            }
            let remaining = &input[current_pos..];
        }
    }
    pub(crate) fn smb_to_bytes<T: Spanned>(&self, spanned: &T) -> proc_macro2::TokenStream {
        let start_byte = self.value.clone();
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
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T) -> proc_macro2::TokenStream {
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
    pub(crate) fn smb_to_bytes<T: Spanned>(&self, spanned: &T) -> proc_macro2::TokenStream {
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
    pub(crate) fn smb_from_bytes<T: Spanned>(&self, spanned: &T, name: &Ident) -> proc_macro2::TokenStream {
        let start = self.start.clone();
        let length = self.length.clone();

        quote_spanned! {spanned.span() =>
            current_pos = #start + #length;
            let remaining = &input[current_pos..];
            let #name = ::std::marker::PhantomData;
        }
    }
    pub(crate) fn smb_to_bytes<T: Spanned>(&self, spanned: &T) -> proc_macro2::TokenStream {
        let start = self.start.clone();
        let length = self.length.clone();
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
            // if let Ok(Meta::List(l)) = attr.parse_nested_meta() {
            //     if let Some(ident) = l.path.get_ident() {
            //         if ident == "repr" && l.nested.len() == 1 {
            //             return Ok(Self {
            //                 ident: l.nested[0].clone()
            //             });
            //         }
            //     }
            // }
        }
        Err(darling::Error::custom("Could not derive 'repr' type"))
    }
}