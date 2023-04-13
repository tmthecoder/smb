use std::fmt::Debug;

use proc_macro2::Ident;
use quote::quote;
use syn::spanned::Spanned;

use crate::{CreatorFn, SMBDeriveError};
use crate::field_mapping::{smb_to_bytes, SMBFieldMapping};

pub(crate) struct ToBytesCreator {}

impl CreatorFn for ToBytesCreator {
    fn call<T: Spanned + PartialEq + Eq + Debug>(self, mapping: Result<SMBFieldMapping<T>, SMBDeriveError<T>>, name: &Ident) -> Result<proc_macro2::TokenStream, SMBDeriveError<T>> {
        to_bytes_parser_impl(mapping, name)
    }
}

fn to_bytes_parser_impl<T: Spanned + PartialEq + Eq + Debug>(mapping: Result<SMBFieldMapping<T>, SMBDeriveError<T>>, name: &Ident) -> Result<proc_macro2::TokenStream, SMBDeriveError<T>> {
    let mapping = mapping?;
    let to_bytes = smb_to_bytes(&mapping);

    Ok(quote! {
        impl ::smb_core::SMBToBytes for #name {
            fn smb_from_bytes(&self) -> Vec<u8> {
                #to_bytes
            }
        }
    })
}