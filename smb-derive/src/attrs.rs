use darling::{FromDeriveInput, FromField, FromMeta};
use proc_macro2::Ident;
use quote::{format_ident, quote, quote_spanned, ToTokens};
use syn::{Attribute, DeriveInput, Meta, NestedMeta, parse_str, Path, Type, TypePath};
use syn::spanned::Spanned;

#[derive(Debug, FromDeriveInput, FromField, Default, PartialEq, Eq)]
#[darling(attributes(direct))]
pub struct Direct {
    pub start: usize,
}

impl Direct {
    pub(crate) fn get_smb_message_info<T: Spanned>(&self, spanned: &T, name: &Ident, ty: &Type) -> proc_macro2::TokenStream {
        let start = self.start;
        quote_spanned! { spanned.span() =>
            let (remaining, #name) = <#ty>::parse_smb_message(&input[#start..])?;
            current_pos = #name.smb_byte_size() + #start;
        }
    }
}

#[derive(Debug, FromMeta, PartialEq, Eq)]
pub struct DirectInner {
    pub start: usize,
    #[darling(rename = "type")]
    pub ty: String,
    #[darling(default)]
    pub subtract: usize,
}

impl DirectInner {
    fn get_smb_message_info<T: Spanned>(&self, name: &str, spanned: &T) -> proc_macro2::TokenStream {
        let start = self.start;
        let subtract = self.subtract;
        let name = format_ident!("{}", name);
        let ty = &self.ty;
        let (ty, chunk) = if self.ty != "direct" {
            let ty = Type::Path(TypePath {
                qself: None,
                path: Path::from(Ident::new(ty, spanned.span())),
            });
            let chunk = quote! {
                let (remaining, #name) = <#ty>::parse_smb_message(&input[#start..])?;
            };
            (ty, chunk)
        } else {
            let chunk = quote! { let #name = current_pos };
            let ty = Type::Path(TypePath {
                qself: None,
                path: Path::from(Ident::new("usize", spanned.span())),
            });
            (ty, chunk)
        };
        quote_spanned! {spanned.span()=>
            #chunk
            let #name = #name - #subtract as #ty;
        }
    }
}

#[derive(Debug, FromDeriveInput, FromField, PartialEq, Eq)]
#[darling(attributes(buffer))]
pub struct Buffer {
    pub offset: DirectInner,
    pub length: DirectInner,
}

impl Buffer {
    pub(crate) fn get_smb_message_info<T: Spanned>(&self, spanned: &T, name: &Ident) -> proc_macro2::TokenStream {
        // let offset_start = self.offset.start;
        // let offset_type = format_ident!("{}", &self.offset.ty);
        // let offset_subtract = self.offset.subtract;
        // let offset_block = if &self.offset.ty != "direct" {
        //     quote! {
        //         let (remaining, offset) = <#offset_type>::parse_smb_message(&input[#offset_start..])?;
        //         current_pos = offset.smb_byte_size() + #offset_start;
        //     }
        // } else {
        //     quote! {
        //         let offset = current_pos;
        //     }
        // };
        //
        // let length_start = self.length.start;
        // let length_type = format_ident!("{}", &self.length.ty);
        // let length_subtract = self.length.subtract;

        let offset = self.offset.get_smb_message_info("offset", spanned);
        let length = self.length.get_smb_message_info("length", spanned);

        quote_spanned! { spanned.span() =>
            #offset
            #length
            let buf_end = offset as usize + length as usize;
            let #name = input[(offset as usize)..].to_vec();
            let remaining = &input[buf_end..];
        }
    }
}

#[derive(Debug, FromDeriveInput, FromField, PartialEq, Eq)]
#[darling(attributes(vector))]
pub struct Vector {
    pub count: DirectInner,
    pub order: usize,
    #[darling(default)]
    pub align: usize,
}

impl Vector {
    pub(crate) fn get_smb_message_info<T: Spanned>(&self, spanned: &T, name: &Ident, ty: &Type) -> proc_macro2::TokenStream {
        let count = self.count.get_smb_message_info("item_count", spanned);
        let align = self.align;

        quote_spanned! { spanned.span() =>
            #count
            if #align > 0 && current_pos % #align != 0 {
                current_pos += 8 - (current_pos % #align);
            }
            let mut remaining = &input[current_pos..];
            let (remaining, #name): (&[u8], #ty) = ::smb_core::SMBVecFromBytes::parse_smb_message_vec(remaining, item_count as usize)?;
            current_pos += #name.smb_byte_size();
        }
    }
}

#[derive(Debug, FromDeriveInput, FromField, Default)]
#[darling(attributes(byte_tag))]
pub struct ByteTag {
    pub value: u8,
}

#[derive(FromDeriveInput, FromField, Default, Debug)]
#[darling(attributes(string_tag))]
pub struct StringTag {
    pub value: String,
}

#[derive(Debug)]
pub struct Repr {
    pub ident: NestedMeta,
}

#[derive(Debug, FromDeriveInput, FromField, PartialEq, Eq)]
#[darling(attributes(skip))]
pub struct Skip {
    pub start: usize,
    pub length: usize,
}

impl Skip {
    pub(crate) fn get_smb_message_info<T: Spanned>(&self, spanned: &T, name: &Ident) -> proc_macro2::TokenStream {
        let start = self.start;
        let length = self.length;

        quote_spanned! {spanned.span() =>
            current_pos = #start + #length;
            let remaining = &input[current_pos..];
            let #name = ::std::marker::PhantomData;
        }
    }
}

impl FromDeriveInput for Repr {
    fn from_derive_input(input: &DeriveInput) -> darling::Result<Self> {
        Self::from_attributes(&input.attrs)
    }
}

impl Repr {
    pub fn from_attributes(attrs: &[Attribute]) -> darling::Result<Self> {
        for attr in attrs.iter() {
            if let Ok(Meta::List(l)) = attr.parse_meta() {
                if let Some(ident) = l.path.get_ident() {
                    if ident == "repr" && l.nested.len() == 1 {
                        return Ok(Self {
                            ident: l.nested[0].clone()
                        });
                    }
                }
            }
        }
        Err(darling::Error::custom("Could not derive 'repr' type"))
    }
}