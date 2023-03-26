use darling::{FromDeriveInput, FromField, FromMeta};
use syn::{DeriveInput, Meta, NestedMeta, Type};

#[derive(Debug, FromDeriveInput, FromField, Default, PartialEq, Eq)]
#[darling(attributes(direct))]
pub struct Direct {
    pub start: usize,
}

#[derive(Debug, FromMeta, PartialEq, Eq)]
pub struct DirectInner {
    pub start: usize,
    pub ty: Type,
}

#[derive(Debug, FromDeriveInput, FromField, PartialEq, Eq)]
#[darling(attributes(buffer))]
pub struct Buffer {
    pub offset: DirectInner,
    pub length: DirectInner,
}

#[derive(Debug, FromDeriveInput, FromField, PartialEq, Eq)]
#[darling(attributes(vector))]
pub struct Vector {
    pub count: DirectInner,
    pub start: usize,
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

impl FromDeriveInput for Repr {
    fn from_derive_input(input: &DeriveInput) -> darling::Result<Self> {
        for attr in input.attrs.iter() {
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
        Err(darling::Error::custom("invalid input"))
    }
}