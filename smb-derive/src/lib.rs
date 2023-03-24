extern crate proc_macro;
use proc_macro::TokenStream;

use syn::{parse_macro_input, DeriveInput};
use quote::quote;

/// Example of [function-like procedural macro][1].
///
/// [1]: https://doc.rust-lang.org/reference/procedural-macros.html#function-like-procedural-macros
#[proc_macro]
pub fn my_macro(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let tokens = quote! {
        #input

        struct Hello;
    };

    tokens.into()
}

/// Example of user-defined [derive mode macro][1]
///
/// [1]: https://doc.rust-lang.org/reference/procedural-macros.html#derive-mode-macros
#[proc_macro_derive(SMBFromBytes, attributes(start, end))]
pub fn smb_from_bytes(_input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(_input as DeriveInput);

    println!("input: {:?}" ,input);

    let tokens = quote! {
    };


    tokens.into()
}

// pub trait SMBFromBytes {
//
// }

// pub trait SMBToBytes {}

#[proc_macro_derive(SMBToBytes)]
pub fn smb_to_bytes(_input: TokenStream) -> TokenStream {
    _input
}