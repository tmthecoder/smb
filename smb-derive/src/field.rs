use std::cmp::{min, Ordering};
use std::fmt::Debug;

use proc_macro2::Ident;
use quote::{format_ident, quote, quote_spanned};
use syn::{Field, Type};
use syn::spanned::Spanned;

use crate::{get_value_type, SMBDeriveError};
use crate::attrs::{Buffer, Direct, Skip, Vector};

#[derive(Debug, PartialEq, Eq)]
pub struct SMBField<'a, T: Spanned> {
    spanned: &'a T,
    name: Ident,
    ty: Type,
    val_type: SMBFieldType,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SMBFieldType {
    Direct(Direct),
    Buffer(Buffer),
    Vector(Vector),
    Skip(Skip),
}

impl<'a, T: Spanned> SMBField<'a, T> {
    pub(crate) fn new(spanned: &'a T, name: Ident, ty: Type, val_type: SMBFieldType) -> Self {
        Self {
            spanned,
            name,
            ty,
            val_type,
        }
    }

    pub(crate) fn get_smb_message_info(&self) -> proc_macro2::TokenStream {
        let name = &self.name;
        let field = self.spanned;
        let ty = &self.ty;
        self.val_type.get_smb_message_info(name, field, ty)
    }

    pub(crate) fn get_name(&self) -> proc_macro2::TokenStream {
        let name = &self.name;
        let field = &self.spanned;
        quote_spanned! {field.span() => #name}
    }
}

impl<'a, T: Spanned + Debug> SMBField<'a, T> {
    fn error(spanned: &T) -> proc_macro2::TokenStream {
        quote_spanned! {spanned.span()=>
            ::std::compile_error!("Error generating byte size for field")
        }
    }

    pub(crate) fn get_named_token(&self) -> proc_macro2::TokenStream {
        format!("self.{}", &self.name.to_string()).parse()
            .unwrap_or_else(|_e| Self::error(self.spanned))
    }

    pub(crate) fn get_unnamed_token(&self, idx: usize) -> proc_macro2::TokenStream {
        format!("self.{}", idx).parse()
            .unwrap_or_else(|_e| Self::error(self.spanned))
    }

    pub(crate) fn get_enum_token(&self) -> proc_macro2::TokenStream {
        let ty = &self.ty;
        quote! {
            (*self as #ty)
        }
    }

    pub(crate) fn get_smb_message_size(&self, size_tokens: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
        quote_spanned! {self.spanned.span()=>
            ::smb_core::SMBByteSize::smb_byte_size(&#size_tokens)
        }
    }
}

impl<'a> SMBField<'a, Field> {
    pub(crate) fn from_iter<U: Iterator<Item=&'a Field>>(fields: U) -> Result<Vec<Self>, SMBDeriveError<Field>> {
        fields.enumerate().map(|(idx, field)| {
            let val_type = get_value_type(field)?;
            let name = if let Some(x) = &field.ident {
                x.clone()
            } else {
                format_ident!("val_{}", idx)
            };
            Ok(SMBField::new(
                field,
                name,
                field.ty.clone(),
                val_type,
            ))
        }).collect::<Vec<Result<SMBField<Field>, SMBDeriveError<Field>>>>()
            .into_iter()
            .collect::<Result<Vec<SMBField<Field>>, SMBDeriveError<Field>>>()
    }
}

impl SMBFieldType {
    fn get_smb_message_info<T: Spanned>(&self, name: &Ident, field: &T, ty: &Type) -> proc_macro2::TokenStream {
        match self {
            SMBFieldType::Direct(direct) => direct.get_smb_message_info(field, name, ty),
            SMBFieldType::Buffer(buffer) => buffer.get_smb_message_info(field, name),
            SMBFieldType::Vector(vector) => vector.get_smb_message_info(field, name, ty),
            SMBFieldType::Skip(skip) => skip.get_smb_message_info(field, name)
        }
    }
}

impl PartialOrd for SMBFieldType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.weight_of_enum() == other.weight_of_enum() {
            Some(self.find_start_val().cmp(&other.find_start_val()))
        } else {
            Some(self.weight_of_enum().cmp(&other.weight_of_enum()))
        }
    }
}

impl<'a, T: Spanned + PartialEq + Eq> PartialOrd for SMBField<'a, T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.val_type.partial_cmp(&other.val_type)
    }
}

impl<'a, T: Spanned + PartialEq + Eq> Ord for SMBField<'a, T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.val_type.cmp(&other.val_type)
    }
}

impl Ord for SMBFieldType {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl SMBFieldType {
    fn find_start_val(&self) -> usize {
        match self {
            Self::Direct(x) => x.start,
            Self::Buffer(x) => min(x.length.start, x.offset.start),
            Self::Vector(x) => x.order,
            Self::Skip(x) => x.start
        }
    }

    fn weight_of_enum(&self) -> usize {
        match self {
            Self::Direct(_) | Self::Skip(_) => 0,
            Self::Buffer(_) | Self::Vector(_) => 1,
        }
    }
}
