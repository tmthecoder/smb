use std::fmt::Debug;

use proc_macro2::Ident;
use quote::quote;
use syn::spanned::Spanned;

use crate::{CreatorFn, SMBDeriveError};
use crate::field_mapping::{smb_from_bytes, SMBFieldMapping};

pub(crate) struct FromBytesCreator {}

impl CreatorFn for FromBytesCreator {
    fn call<T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq + Debug>(self, mappings: Result<Vec<SMBFieldMapping<T, U>>, SMBDeriveError<U>>, name: &Ident) -> Result<proc_macro2::TokenStream, SMBDeriveError<U>> {
        create_parser_impl(mappings, name)
    }
}

fn create_parser_impl<T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq + Debug>(mapping: Result<Vec<SMBFieldMapping<T, U>>, SMBDeriveError<U>>, name: &Ident) -> Result<proc_macro2::TokenStream, SMBDeriveError<U>> {
    let mapping = mapping?;
    let parser = smb_from_bytes(&mapping[0]);

    Ok(quote! {
        impl ::smb_core::SMBFromBytes for #name {
            #[allow(unused_variables, unused_assignments, unnecessary_cast)]
            fn smb_from_bytes(input: &[u8]) -> ::smb_core::SMBParseResult<&[u8], Self, ::smb_core::error::SMBError> {
                #parser
            }
        }
    })
}