use std::cmp::{min, Ordering};
use std::fmt::Debug;

use darling::FromAttributes;
use proc_macro2::Ident;
use quote::{format_ident, quote, quote_spanned};
use syn::{Attribute, Field, Type};
use syn::spanned::Spanned;

use crate::attrs::{Buffer, ByteTag, Direct, Skip, StringTag, Vector};
use crate::SMBDeriveError;

#[derive(Debug, PartialEq, Eq)]
pub struct SMBField<'a, T: Spanned> {
    spanned: &'a T,
    name: Ident,
    ty: Type,
    val_type: Vec<SMBFieldType>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SMBFieldType {
    Direct(Direct),
    Buffer(Buffer),
    Vector(Vector),
    Skip(Skip),
    ByteTag(ByteTag),
    StringTag(StringTag),
}

impl<'a, T: Spanned> SMBField<'a, T> {
    pub(crate) fn new(spanned: &'a T, name: Ident, ty: Type, val_type: Vec<SMBFieldType>) -> Self {
        Self {
            spanned,
            name,
            ty,
            val_type,
        }
    }

    pub(crate) fn smb_from_bytes(&self) -> proc_macro2::TokenStream {
        let name = &self.name;
        let field = self.spanned;
        let ty = &self.ty;
        let all_bytes = self.val_type.iter().map(|field_ty| field_ty.smb_from_bytes(name, field, ty));
        quote! {
            #(#all_bytes)*
        }
    }

    pub(crate) fn smb_to_bytes(&self) -> proc_macro2::TokenStream {
        let name = &self.name;
        let field = self.spanned;
        let all_bytes = self.val_type.iter().map(|field_ty| field_ty.smb_to_bytes(name, field));
        quote! {
            #(#all_bytes)*
        }
    }

    pub(crate) fn attr_byte_size(&self) -> usize {
        self.val_type.iter().fold(0, |x, inc| x + inc.attr_size())
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
            let val_types = field.attrs.iter().map(|attr| get_field_types(field, &[attr.clone()])).collect::<Result<Vec<SMBFieldType>, SMBDeriveError<Field>>>()?;
            let name = if let Some(x) = &field.ident {
                x.clone()
            } else {
                format_ident!("val_{}", idx)
            };
            Ok(SMBField::new(
                field,
                name,
                field.ty.clone(),
                val_types,
            ))
        }).collect::<Vec<Result<SMBField<Field>, SMBDeriveError<Field>>>>()
            .into_iter()
            .collect::<Result<Vec<SMBField<Field>>, SMBDeriveError<Field>>>()
    }
}

impl SMBFieldType {
    fn smb_from_bytes<T: Spanned>(&self, name: &Ident, field: &T, ty: &Type) -> proc_macro2::TokenStream {
        match self {
            SMBFieldType::Direct(direct) => direct.smb_from_bytes(field, name, ty),
            SMBFieldType::Buffer(buffer) => buffer.smb_from_bytes(field, name),
            SMBFieldType::Vector(vector) => vector.smb_from_bytes(field, name, ty),
            SMBFieldType::Skip(skip) => skip.smb_from_bytes(field, name),
            SMBFieldType::ByteTag(byte_tag) => byte_tag.smb_from_bytes(field),
            SMBFieldType::StringTag(string_tag) => string_tag.smb_from_bytes(field),
        }
    }
    fn smb_to_bytes<T: Spanned>(&self, name: &Ident, field: &T) -> proc_macro2::TokenStream {
        match self {
            SMBFieldType::Direct(direct) => direct.smb_to_bytes(field, name),
            SMBFieldType::Buffer(buffer) => buffer.smb_to_bytes(field, name),
            SMBFieldType::Vector(vector) => vector.smb_to_bytes(field, name),
            SMBFieldType::Skip(skip) => skip.smb_to_bytes(field, name),
            SMBFieldType::ByteTag(byte_tag) => byte_tag.smb_to_bytes(field),
            SMBFieldType::StringTag(string_tag) => string_tag.smb_to_bytes(field),
        }
    }
    fn attr_size(&self) -> usize {
        match self {
            SMBFieldType::Direct(direct) => direct.attr_byte_size(),
            SMBFieldType::Buffer(buffer) => buffer.attr_byte_size(),
            SMBFieldType::Vector(vector) => vector.attr_byte_size(),
            SMBFieldType::Skip(skip) => skip.attr_byte_size(),
            SMBFieldType::ByteTag(byte_tag) => byte_tag.attr_byte_size(),
            SMBFieldType::StringTag(string_tag) => string_tag.attr_byte_size(),
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
            Self::Skip(x) => x.start,
            Self::ByteTag(x) => x.order,
            Self::StringTag(x) => x.order,
        }
    }

    fn weight_of_enum(&self) -> usize {
        match self {
            Self::ByteTag(_) | Self::StringTag(_) => 0,
            Self::Direct(_) | Self::Skip(_) => 1,
            Self::Buffer(_) | Self::Vector(_) => 2,
        }
    }
}

impl FromAttributes for SMBFieldType {
    fn from_attributes(attrs: &[Attribute]) -> darling::Result<Self> {
        if let Ok(buffer) = Buffer::from_attributes(attrs) {
            Ok(SMBFieldType::Buffer(buffer))
        } else if let Ok(direct) = Direct::from_attributes(attrs) {
            Ok(SMBFieldType::Direct(direct))
        } else if let Ok(vector) = Vector::from_attributes(attrs) {
            Ok(SMBFieldType::Vector(vector))
        } else if let Ok(skip) = Skip::from_attributes(attrs) {
            Ok(SMBFieldType::Skip(skip))
        } else if let Ok(string_tag) = StringTag::from_attributes(attrs) {
            Ok(SMBFieldType::StringTag(string_tag))
        } else {
            let byte_tag = ByteTag::from_attributes(attrs)?;
            Ok(SMBFieldType::ByteTag(byte_tag))
        }
    }
}

fn get_field_types(field: &Field, attrs: &[Attribute]) -> Result<SMBFieldType, SMBDeriveError<Field>> {
    if let Ok(buffer) = Buffer::from_attributes(attrs) {
        Ok(SMBFieldType::Buffer(buffer))
    } else if let Ok(direct) = Direct::from_attributes(attrs) {
        Ok(SMBFieldType::Direct(direct))
    } else if let Ok(vector) = Vector::from_attributes(attrs) {
        Ok(SMBFieldType::Vector(vector))
    } else if let Ok(skip) = Skip::from_attributes(attrs) {
        Ok(SMBFieldType::Skip(skip))
    } else {
        Err(SMBDeriveError::TypeError(field.clone()))
    }
}