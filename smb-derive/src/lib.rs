extern crate proc_macro;

use proc_macro::TokenStream;
use std::fmt::{Debug, Display, Formatter};

use darling::{FromDeriveInput, FromField};
use proc_macro2::Ident;
use quote::{quote, quote_spanned};
use syn::{Data, DeriveInput, Field, parse_macro_input};
use syn::spanned::Spanned;

use crate::attrs::{Buffer, Direct, Skip, Vector};
use crate::field::SMBFieldType;
use crate::field_mapping::{get_enum_field_mapping, get_struct_field_mapping, parse_smb_message, SMBFieldMapping};

mod attrs;
mod field_mapping;
mod field;


#[proc_macro_derive(SMBFromBytes, attributes(direct, buffer, vector, skip, byte_tag, string_tag))]
pub fn smb_from_bytes(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);

    let name = &input.ident;

    let invalid_token: proc_macro2::TokenStream = quote_spanned! {
        input.span() => compile_error!("Invalid or unsupported type")
    };

    let parse_token = match &input.data {
        Data::Struct(structure) => {
            let parent_val_type = parent_value_type(&input);
            let mapping = get_struct_field_mapping(structure, parent_val_type);
            create_parser_impl(mapping, name)
                .unwrap_or_else(|e| match e {
                    SMBDeriveError::TypeError(f) => quote_spanned! {f.span()=>::std::compile_error!("Invalid field for SMB message parsing")},
                    SMBDeriveError::InvalidType => invalid_token
                })
        },
        Data::Enum(_en) => {
            let mapping = get_enum_field_mapping(&input.attrs, &input);
            create_parser_impl(mapping, name)
                .unwrap_or_else(|_e| quote_spanned! {input.span()=>
                    ::std::compile_error!("Invalid enum for SMB message parsing")
                })
        },
        _ => invalid_token
    };

    parse_token.into()
}

fn create_parser_impl<T: Spanned + PartialEq + Eq + Debug>(mapping: Result<SMBFieldMapping<T>, SMBDeriveError<T>>, name: &Ident) -> Result<proc_macro2::TokenStream, SMBDeriveError<T>> {
    let mapping = mapping?;
    let parser = parse_smb_message(&mapping);
    let size = smb_byte_size(&mapping);

    Ok(quote! {
        impl ::smb_core::SMBFromBytes for #name {
            fn smb_byte_size(&self) -> usize {
                #size
            }
            #[allow(unused_variables, unused_assignments)]
            fn parse_smb_message(input: &[u8]) -> ::smb_core::SMBResult<&[u8], Self, ::smb_core::error::SMBError> {
                #parser
            }
        }
    })
}


fn smb_byte_size<T: Spanned + PartialEq + Eq + Debug>(mapping: &SMBFieldMapping<T>) -> proc_macro2::TokenStream {
    mapping.get_mapping_size()
}

fn get_value_type(field: &Field) -> Result<SMBFieldType, SMBDeriveError<Field>> {
    if let Ok(buffer) = Buffer::from_field(field) {
        Ok(SMBFieldType::Buffer(buffer))
    } else if let Ok(direct) = Direct::from_field(field) {
        Ok(SMBFieldType::Direct(direct))
    } else if let Ok(vector) = Vector::from_field(field) {
        Ok(SMBFieldType::Vector(vector))
    } else if let Ok(skip) = Skip::from_field(field) {
        Ok(SMBFieldType::Skip(skip))
    } else {
        Err(SMBDeriveError::TypeError(field.clone()))
    }
}

fn parent_value_type(input: &DeriveInput) -> Option<SMBFieldType> {
    if let Ok(buffer) = Buffer::from_derive_input(input) {
        Some(SMBFieldType::Buffer(buffer))
    } else if let Ok(direct) = Direct::from_derive_input(input) {
        Some(SMBFieldType::Direct(direct))
    } else if let Ok(vector) = Vector::from_derive_input(input) {
        Some(SMBFieldType::Vector(vector))
    } else {
        None
    }
}

#[derive(Debug)]
enum SMBDeriveError<T: Spanned + Debug> {
    TypeError(T),
    InvalidType,
}

impl<T: Spanned + Debug> Display for SMBDeriveError<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TypeError(span) => write!(f, "No type annotation for spannable ${:?} (must be buffer or direct)", span),
            Self::InvalidType => write!(f, "Unsupported or invalid type"),
        }
    }
}

impl<T: Spanned + Debug> std::error::Error for SMBDeriveError<T> {}

#[proc_macro_derive(SMBToBytes)]
pub fn smb_to_bytes(_input: TokenStream) -> TokenStream {
    _input
}