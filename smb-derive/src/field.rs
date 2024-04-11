use std::cmp::{max, Ordering};
use std::fmt::Debug;

use darling::FromAttributes;
use proc_macro2::{Delimiter, Group, Ident, TokenStream, TokenTree};
use quote::{format_ident, quote, quote_spanned};
use syn::{Attribute, Field, Type};
use syn::spanned::Spanned;

use crate::attrs::{AttributeInfo, Buffer, ByteTag, Direct, Skip, SMBEnum, SMBString, StringTag, Vector};
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
    String(SMBString),
    Enum(SMBEnum),
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

    pub(crate) fn spanned(&self) -> &T {
        self.spanned
    }

    pub(crate) fn smb_from_bytes(&self) -> proc_macro2::TokenStream {
        let name = &self.name;
        let field = self.spanned;
        let ty = &self.ty;
        let name_str = name.to_string();
        let all_bytes = self.val_type.iter().map(|field_ty| field_ty.smb_from_bytes(name, field, ty));
        quote! {
            // println!("parse for {:?}", #name_str);
            #(#all_bytes)*
            // println!("end parse for {:?}", #name_str);
        }
    }

    pub(crate) fn smb_to_bytes_struct(&self, variant: bool) -> proc_macro2::TokenStream {
        let name = &self.name;
        let item_name = match variant {
            true => quote! { #name },
            false => quote! { self.#name },
        };
        let name_token = TokenTree::Group(Group::new(Delimiter::Parenthesis, item_name));
        let raw_token = quote! { #name_token };
        let name_token_adj = match variant {
            true => quote! { #name_token },
            false => quote! { &#name_token },
        };
        let field = self.spanned;
        let ty = &self.ty;
        let all_bytes = self.val_type.iter().map(|field_ty| field_ty.smb_to_bytes(&name_token_adj, &raw_token, field));
        quote! {
            #(#all_bytes)*
        }
    }

    pub(crate) fn smb_to_bytes_enum(&self) -> TokenStream {
        let ty = &self.ty;
        let group = TokenTree::Group(Group::new(Delimiter::Parenthesis, quote! {(*self) as #ty}));
        let raw_token = quote! { #group };
        let token_adj = quote! {
            &#group
        };
        let field = self.spanned;
        let all_bytes = self.val_type.iter().map(|field_ty| field_ty.smb_to_bytes(&token_adj, &raw_token, field));
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
    fn error(spanned: &T) -> TokenStream {
        quote_spanned! {spanned.span()=>
            ::std::compile_error!("Error generating byte size for field")
        }
    }

    pub(crate) fn get_named_token(&self) -> TokenStream {
        format!("&self.{}", &self.name.to_string()).parse()
            .unwrap_or_else(|_e| Self::error(self.spanned))
    }

    pub(crate) fn get_unnamed_token(&self, idx: usize) -> TokenStream {
        format!("&self.{}", idx).parse()
            .unwrap_or_else(|_e| Self::error(self.spanned))
    }

    pub(crate) fn get_num_enum_token(&self) -> TokenStream {
        let ty = &self.ty;
        quote! {
           & (*self as #ty)
        }
    }

    pub(crate) fn get_disc_enum_token(&self) -> TokenStream {
        format!("Self::{}", &self.name.to_string()).parse().unwrap_or_else(|_e| Self::error(self.spanned))
    }

    pub(crate) fn get_smb_message_size(&self, size_tokens: TokenStream) -> TokenStream {
        let tmp = SMBFieldType::Skip(Skip::new(0, 0));
        let (start_val, ty) = self.val_type.iter().fold((0, &tmp), |prev, val| {
            if let SMBFieldType::Skip(skip) = val && skip.length + skip.start > prev.0 {
                (skip.length + skip.start, val)
            } else if val.weight_of_enum() == 2 || val.find_start_val() > prev.0 {
                (val.find_start_val(), val)
            } else {
                prev
            }
        });

        let align = if let SMBFieldType::Vector(vec) = ty {
            if vec.align > 0 { vec.align } else { 1 }
        } else if let SMBFieldType::String(str) = ty {
            if str.underlying == "u8" {
                1
            } else {
                2
            }
        } else {
            1
        };

        let offset = if let SMBFieldType::Vector(vec) = ty {
            Some(&vec.offset)
        } else if let SMBFieldType::Buffer(buf) = ty {
            Some(&buf.offset)
        } else {
            None
        };

        let min_start = if let Some(start) = offset.map(|offset| offset.get_pos()) {
            start
        } else {
            0
        };

        if ty.weight_of_enum() == 2 {
            quote_spanned! {self.spanned.span()=>
                let size = ::std::cmp::max(size, #min_start) + ::smb_core::SMBVecByteSize::smb_byte_size_vec(#size_tokens, #align, size);
            }
        } else {
            quote_spanned! {self.spanned.span()=>
                let size = #start_val + ::smb_core::SMBByteSize::smb_byte_size(#size_tokens);
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
    fn smb_from_bytes<T: Spanned>(&self, name: &Ident, field: &T, ty: &Type) -> TokenStream {
        match self {
            SMBFieldType::Direct(direct) => direct.smb_from_bytes(field, name, ty),
            SMBFieldType::Buffer(buffer) => buffer.smb_from_bytes(field, name),
            SMBFieldType::Vector(vector) => vector.smb_from_bytes(field, name, ty),
            SMBFieldType::String(string) => string.smb_from_bytes(field, name),
            SMBFieldType::Enum(smb_enum) => smb_enum.smb_from_bytes(field, name),
            SMBFieldType::Skip(skip) => skip.smb_from_bytes(field, name, ty),
            SMBFieldType::ByteTag(byte_tag) => byte_tag.smb_from_bytes(field),
            SMBFieldType::StringTag(string_tag) => string_tag.smb_from_bytes(field),
        }
    }
    fn smb_to_bytes<T: Spanned>(&self, token: &TokenStream, raw_token: &TokenStream, field: &T) -> TokenStream {
        match self {
            SMBFieldType::Direct(direct) => direct.smb_to_bytes(field, token),
            SMBFieldType::Buffer(buffer) => buffer.smb_to_bytes(field, token),
            SMBFieldType::Vector(vector) => vector.smb_to_bytes(field, raw_token),
            SMBFieldType::String(string) => string.smb_to_bytes(field, raw_token),
            SMBFieldType::Enum(smb_enum) => smb_enum.smb_to_bytes(field, token),
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
            SMBFieldType::String(string) => string.attr_byte_size(),
            SMBFieldType::Enum(smb_enum) => smb_enum.attr_byte_size(),
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
            Self::Direct(x) => match x.start {
                AttributeInfo::Fixed(idx) => idx,
                AttributeInfo::CurrentPos |
                AttributeInfo::Inner(_) |
                AttributeInfo::NullTerminated(_) => x.order
            },
            Self::Enum(x) => match x.start {
                AttributeInfo::Fixed(idx) => idx,
                AttributeInfo::CurrentPos |
                AttributeInfo::Inner(_) |
                AttributeInfo::NullTerminated(_) => x.order
            }
            Self::Buffer(x) => x.order,
            Self::Vector(x) => x.order,
            Self::String(x) => x.order,
            Self::Skip(x) => x.start,
            Self::ByteTag(x) => x.order,
            Self::StringTag(x) => x.order,
        }
    }

    fn weight_of_enum(&self) -> usize {
        match self {
            Self::ByteTag(_) | Self::StringTag(_) => 0,
            Self::Direct(_) | Self::Skip(_) | Self::Enum(_) => 1,
            Self::Buffer(_) | Self::Vector(_) | Self::String(_) => 2,
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
        } else if let Ok(string) = SMBString::from_attributes(attrs) {
            Ok(SMBFieldType::String(string))
        } else if let Ok(smb_enum) = SMBEnum::from_attributes(attrs) {
            // println!("Got enum: {:?}", smb_enum);
            Ok(SMBFieldType::Enum(smb_enum))
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
    SMBFieldType::from_attributes(attrs)
        .map_err(|_e| SMBDeriveError::TypeError(field.clone()))
}