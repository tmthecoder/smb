use std::fmt::Debug;

use proc_macro2::Ident;
use quote::quote;
use syn::spanned::Spanned;

use crate::{CreatorFn, SMBDeriveError};
use crate::field_mapping::{smb_to_bytes, SMBFieldMapping};

pub(crate) struct ToBytesCreator {}

impl CreatorFn for ToBytesCreator {
    fn call<T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq + Debug>(self, mappings: Result<Vec<SMBFieldMapping<T, U>>, SMBDeriveError<U>>, name: &Ident) -> Result<proc_macro2::TokenStream, SMBDeriveError<U>> {
        to_bytes_parser_impl(mappings, name)
    }
}

fn to_bytes_parser_impl<T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq + Debug>(mappings: Result<Vec<SMBFieldMapping<T, U>>, SMBDeriveError<U>>, name: &Ident) -> Result<proc_macro2::TokenStream, SMBDeriveError<U>> {
    let mappings = mappings?;
    let to_bytes = mappings.iter().map(|mapping| smb_to_bytes(mapping));

    Ok(quote! {
        impl ::smb_core::SMBToBytes for #name {
            #[allow(unused_variables, unused_assignments, clippy::needless_borrow, clippy::identity_op, clippy::self_assignment)]
            fn smb_to_bytes(&self) -> Vec<u8> {
                match self {
                    #(#to_bytes)*
                }
            }
        }
    })
}