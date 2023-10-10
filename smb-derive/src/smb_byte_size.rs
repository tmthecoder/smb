use std::fmt::Debug;

use proc_macro2::Ident;
use quote::quote;
use syn::spanned::Spanned;

use crate::{CreatorFn, SMBDeriveError};
use crate::field_mapping::SMBFieldMapping;

pub(crate) struct ByteSizeCreator {}

impl CreatorFn for ByteSizeCreator {
    fn call<T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq + Debug>(self, mapping: Result<SMBFieldMapping<T, U>, SMBDeriveError<U>>, name: &Ident) -> Result<proc_macro2::TokenStream, SMBDeriveError<U>> {
        create_byte_size_impl(mapping, name)
    }
}

fn create_byte_size_impl<T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq + Debug>(mapping: Result<SMBFieldMapping<T, U>, SMBDeriveError<U>>, name: &Ident) -> Result<proc_macro2::TokenStream, SMBDeriveError<U>> {
    let mapping = mapping?;
    let size = smb_byte_size_impl(&mapping);
    Ok(quote! {
        impl ::smb_core::SMBByteSize for #name {
            #[allow(unused_variables, unused_assignments, modulo_one)]
            fn smb_byte_size(&self) -> usize {
                #size
            }
        }
    })
}

fn smb_byte_size_impl<T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq + Debug>(mapping: &SMBFieldMapping<T, U>) -> proc_macro2::TokenStream {
    mapping.get_mapping_size()
}