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
use crate::field_mapping::{get_enum_field_mapping, get_struct_field_mapping, SMBFieldMapping};
use crate::smb_byte_size::ByteSizeCreator;
use crate::smb_from_bytes::FromBytesCreator;
use crate::smb_to_bytes::ToBytesCreator;

mod attrs;
mod field_mapping;
mod field;
mod smb_from_bytes;
mod smb_byte_size;
mod smb_to_bytes;


#[proc_macro_derive(SMBFromBytes, attributes(smb_direct, smb_buffer, smb_vector, smb_skip, smb_byte_tag, smb_string_tag))]
pub fn smb_from_bytes(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);

    let parse_token = derive_impl_creator(input, FromBytesCreator {});

    parse_token.into()
}

#[proc_macro_derive(SMBToBytes, attributes(smb_direct, smb_buffer, smb_vector, smb_skip, smb_byte_tag, smb_string_tag))]
pub fn smb_to_bytes(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);

    let parse_token = derive_impl_creator(input, ToBytesCreator {});

    parse_token.into()
}

#[proc_macro_derive(SMBByteSize, attributes(smb_direct, smb_buffer, smb_vector, smb_skip, smb_byte_tag, smb_string_tag))]
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

    let parse_token = match &input.data {
        Data::Struct(structure) => {
            let parent_val_type = parent_value_type(&input);
            let mapping = get_struct_field_mapping(structure, parent_val_type);
            creator.call(mapping, name)
                .unwrap_or_else(|e| match e {
                    SMBDeriveError::TypeError(f) => quote_spanned! {f.span()=>::std::compile_error!("Invalid field for SMB message parsing")},
                    SMBDeriveError::InvalidType => invalid_token
                })
        },
        Data::Enum(_en) => {
            let mapping = get_enum_field_mapping(&input.attrs, &input);
            creator.call(mapping, name)
                .unwrap_or_else(|_e| quote_spanned! {input.span()=>
                    ::std::compile_error!("Invalid enum for SMB message parsing")
                })
        },
        _ => invalid_token
    };

    parse_token
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

trait CreatorFn {
    fn call<T: Spanned + PartialEq + Eq + Debug>(self, mapping: Result<SMBFieldMapping<T>, SMBDeriveError<T>>, name: &Ident) -> Result<proc_macro2::TokenStream, SMBDeriveError<T>>;
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