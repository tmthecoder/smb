use std::cmp::{max, Ordering};
use std::fmt::Debug;

use darling::FromAttributes;
use proc_macro2::{Delimiter, Group, Ident, TokenTree};
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

    pub(crate) fn smb_to_bytes_struct(&self) -> proc_macro2::TokenStream {
        let name = &self.name;
        let name_self = TokenTree::Group(Group::new(Delimiter::Parenthesis, quote! {self.#name}));
        let field = self.spanned;
        let all_bytes = self.val_type.iter().map(|field_ty| field_ty.smb_to_bytes(&name_self, field));
        quote! {
            #(#all_bytes)*
        }
    }

    pub(crate) fn smb_to_bytes_enum(&self) -> proc_macro2::TokenStream {
        let ty = &self.ty;
        let group = TokenTree::Group(proc_macro2::Group::new(Delimiter::Parenthesis, quote! {(*self) as #ty}));
        let field = self.spanned;
        let all_bytes = self.val_type.iter().map(|field_ty| field_ty.smb_to_bytes(&group, field));
        quote! {
            #(#all_bytes)*
        }
    }

    pub(crate) fn attr_byte_size(&self) -> usize {
        let mut current_ptr = 0;
        let mut skip_ptr = 0;
        for field_type in self.val_type.iter() {
            if let SMBFieldType::Skip(s) = field_type {
                skip_ptr = s.start + s.length;
            } else {
                current_ptr += field_type.attr_size();
            }
        }
        max(current_ptr, skip_ptr)
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
        let tmp = SMBFieldType::Skip(Skip::new(0, 0));
        let (start_val, ty) = self.val_type.iter().fold((0, &tmp), |prev, val| {
            if let SMBFieldType::Skip(skip) = val && skip.length + skip.start > prev.0 { (skip.length + skip.start, val) } else if val.weight_of_enum() == 2 || val.find_start_val() > prev.0 { (val.find_start_val(), val) } else { prev }
        });

        let align = if let SMBFieldType::Vector(vec) = ty {
            if vec.align > 0 { vec.align } else { 1 }
        } else {
            1
        };

        let offset = if let SMBFieldType::Vector(vec) = ty {
            vec.offset.as_ref()
        } else if let SMBFieldType::Buffer(buf) = ty {
            Some(&buf.offset)
        } else {
            None
        };

        let min_start = if let Some(start) = offset.map(|offset| offset.min_val.saturating_sub(offset.subtract)) {
            start
        } else {
            0
        };

        if ty.weight_of_enum() == 2 {
            quote_spanned! {self.spanned.span()=>
                // let align_value = if size % #align == 0 {
                //     0
                // } else {
                //     #align - (size % #align)
                // };
                let size = ::std::cmp::max(size, #min_start) + ::smb_core::SMBVecByteSize::smb_byte_size_vec(&#size_tokens, #align, size);
            }
        } else {
            quote_spanned! {self.spanned.span()=>
                let size = #start_val + ::smb_core::SMBByteSize::smb_byte_size(&#size_tokens);
            }
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
            SMBFieldType::Skip(skip) => skip.smb_from_bytes(field, name, ty),
            SMBFieldType::ByteTag(byte_tag) => byte_tag.smb_from_bytes(field),
            SMBFieldType::StringTag(string_tag) => string_tag.smb_from_bytes(field),
        }
    }
    fn smb_to_bytes<T: Spanned>(&self, token: &TokenTree, field: &T) -> proc_macro2::TokenStream {
        match self {
            SMBFieldType::Direct(direct) => direct.smb_to_bytes(field, token),
            SMBFieldType::Buffer(buffer) => buffer.smb_to_bytes(field, token),
            SMBFieldType::Vector(vector) => vector.smb_to_bytes(field, token),
            SMBFieldType::Skip(skip) => skip.smb_to_bytes(field),
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
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl<'a, T: Spanned + PartialEq + Eq> PartialOrd for SMBField<'a, T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl<'a, T: Spanned + PartialEq + Eq> Ord for SMBField<'a, T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.val_type.cmp(&other.val_type)
    }
}

impl Ord for SMBFieldType {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.weight_of_enum() == other.weight_of_enum() {
            self.find_start_val().cmp(&other.find_start_val())
        } else {
            self.weight_of_enum().cmp(&other.weight_of_enum())
        }
    }
}

impl SMBFieldType {
    fn find_start_val(&self) -> usize {
        match self {
            Self::Direct(x) => x.start,
            Self::Buffer(x) => x.order,
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