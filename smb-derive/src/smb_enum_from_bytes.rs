use std::fmt::Debug;

use proc_macro2::Ident;
use quote::quote;
use syn::spanned::Spanned;

use crate::{CreatorFn, SMBDeriveError};
use crate::field_mapping::{smb_enum_from_bytes, SMBFieldMapping};

pub(crate) struct EnumFromBytesCreator {}

impl CreatorFn for EnumFromBytesCreator {
    fn call<T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq + Debug>(self, mapping: Result<Vec<SMBFieldMapping<T, U>>, SMBDeriveError<U>>, name: &Ident) -> Result<proc_macro2::TokenStream, SMBDeriveError<U>> {
        enum_from_bytes_parser_impl(mapping, name)
    }
}

fn enum_from_bytes_parser_impl<T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq + Debug>(mappings: Result<Vec<SMBFieldMapping<T, U>>, SMBDeriveError<U>>, name: &Ident) -> Result<proc_macro2::TokenStream, SMBDeriveError<U>> {
    let mappings = mappings?;
    let parser = mappings.iter().map(|mapping| smb_enum_from_bytes(mapping));
    Ok(quote! {
        impl ::smb_core::SMBEnumFromBytes for #name {
            #[allow(unused_variables, unused_assignments)]
            fn smb_enum_from_bytes(input: &[u8], discriminator: u64) -> ::smb_core::SMBParseResult<&[u8], Self, ::smb_core::error::SMBError> {
                println!("disc: {:?}, input: {:02x?}", discriminator, input);
                match discriminator {
                    #(#parser)*
                    _ => Err(::smb_core::error::SMBError::parse_error("Invalid discriminator"))
                }
            }
        }
    })
}