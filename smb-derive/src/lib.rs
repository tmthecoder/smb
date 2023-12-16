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


#[proc_macro_derive(SMBFromBytes, attributes(smb_direct, smb_buffer, smb_vector, smb_string, smb_enum, smb_skip, smb_byte_tag, smb_string_tag))]
pub fn smb_from_bytes(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);

    let parse_token = derive_impl_creator(input, FromBytesCreator {});

    parse_token.into()
}

#[proc_macro_derive(SMBEnumFromBytes, attributes(smb_direct, smb_buffer, smb_vector, smb_string, smb_enum, smb_skip, smb_byte_tag, smb_string_tag, smb_discriminator))]
pub fn smb_enum_from_bytes(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);

    let parse_token = derive_impl_creator(input, EnumFromBytesCreator {});

    parse_token.into()
}

#[proc_macro_derive(SMBToBytes, attributes(smb_direct, smb_buffer, smb_vector, smb_string, smb_enum, smb_skip, smb_byte_tag, smb_string_tag))]
pub fn smb_to_bytes(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);

    let parse_token = derive_impl_creator(input, ToBytesCreator {});

    parse_token.into()
}

#[proc_macro_derive(SMBByteSize, attributes(smb_direct, smb_buffer, smb_vector, smb_string, smb_enum, smb_skip, smb_byte_tag, smb_string_tag))]
pub fn smb_byte_size(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);

    let parse_token = derive_impl_creator(input, ByteSizeCreator {});

    parse_token.into()
}


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
                    println!("ENUM MAPPING: {:?}", mapping);
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


fn parent_attrs(input: &DeriveInput) -> Vec<SMBFieldType> {
    input.attrs.iter().map(|attr| {
        SMBFieldType::from_attributes(&[attr.clone()])
    }).collect::<darling::Result<Vec<SMBFieldType>>>()
        .unwrap_or(vec![])
}

trait CreatorFn {
    fn call<T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq + Debug>(self, mapping: Result<Vec<SMBFieldMapping<T, U>>, SMBDeriveError<U>>, name: &Ident) -> Result<proc_macro2::TokenStream, SMBDeriveError<U>>;
}

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