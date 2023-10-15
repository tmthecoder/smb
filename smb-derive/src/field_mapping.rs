use std::fmt::Debug;

use darling::FromAttributes;
use proc_macro2::Ident;
use quote::{format_ident, quote};
use syn::{AngleBracketedGenericArguments, Attribute, DataStruct, DeriveInput, Field, Fields, GenericArgument, Path, PathArguments, PathSegment, Token, Type, TypePath};
use syn::parse::Parse;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::token::PathSep;

use crate::attrs::{Direct, DirectStart, Repr};
use crate::field::{SMBField, SMBFieldType};
use crate::SMBDeriveError;

#[derive(Debug, PartialEq, Eq)]
pub struct SMBFieldMapping<'a, T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq> {
    parent: SMBField<'a, T>,
    fields: Vec<SMBField<'a, U>>,
    mapping_type: SMBFieldMappingType,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SMBFieldMappingType {
    NamedStruct,
    UnnamedStruct,
    Enum,
    Unit,
}

impl<T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq + Debug> SMBFieldMapping<'_, T, U> {
    pub(crate) fn get_mapping_size(&self) -> proc_macro2::TokenStream {
        let parent_size = self.parent.attr_byte_size();
        let size = match &self.mapping_type {
            SMBFieldMappingType::NamedStruct => self.fields.iter().map(|f| {
                let token = f.get_named_token();
                f.get_smb_message_size(token)
            }).collect(),
            SMBFieldMappingType::UnnamedStruct => self.fields.iter().enumerate().map(|(idx, f)| {
                let token = f.get_unnamed_token(idx);
                f.get_smb_message_size(token)
            }).collect(),
            SMBFieldMappingType::Enum => self.fields.iter().map(|f| {
                let token = f.get_enum_token();
                f.get_smb_message_size(token)
            }).collect(),
            SMBFieldMappingType::Unit => vec![quote! {

            }]
        };

        quote! {
            let size = #parent_size;
            #(#size)*
            size
        }
    }
}

pub(crate) fn get_enum_field_mapping<'a>(enum_attributes: &[Attribute], input: &'a DeriveInput, parent_attrs: Vec<SMBFieldType>) -> Result<SMBFieldMapping<'a, DeriveInput, DeriveInput>, SMBDeriveError<DeriveInput>> {
    let repr_type = Repr::from_attributes(enum_attributes)
        .map_err(|_e| SMBDeriveError::TypeError(input.clone()))?;
    let identity = &repr_type.ident;
    let ty = Type::Path(TypePath {
        qself: None,
        path: Path::from(Ident::new(&quote! {#identity}.to_string(), input.span())),
    });
    let smb_field = SMBField::new(
        input,
        format_ident!("enum_field"),
        ty.clone(),
        vec![SMBFieldType::Direct(Direct {
            start: DirectStart::Location(0),
            order: 0,
        })],
    );
    let parent = SMBField::new(input, format_ident!("enum_outer"), ty, parent_attrs);
    Ok(SMBFieldMapping {
        parent,
        fields: vec![smb_field],
        mapping_type: SMBFieldMappingType::Enum,
    })
}

pub(crate) fn get_struct_field_mapping(structure: &DataStruct, parent_attrs: Vec<SMBFieldType>) -> Result<SMBFieldMapping<Fields, Field>, SMBDeriveError<Field>> {
    if structure.fields.len() == 1 {
        let field = structure.fields.iter().next()
            .ok_or(SMBDeriveError::InvalidType)?;
        let (field, val_types) = if !parent_attrs.is_empty() {
            (field, parent_attrs)
        } else {
            (field, vec![SMBFieldType::Direct(Direct {
                start: DirectStart::Location(0),
                order: 0,
            })])
        };

        let name = if let Some(x) = &field.ident {
            x.clone()
        } else {
            format_ident!("val_0")
        };


        let fields = vec![SMBField::new(field, name, field.ty.clone(), val_types)];

        let parent = SMBField::new(&structure.fields, format_ident!("single_base"), field.ty.clone(), vec![]);

        return if field.ident.is_some() {
            Ok(SMBFieldMapping {
                parent,
                fields,
                mapping_type: SMBFieldMappingType::NamedStruct,
            })
        } else {
            Ok(SMBFieldMapping {
                parent,
                fields,
                mapping_type: SMBFieldMappingType::UnnamedStruct,
            })
        };
    }
    let mut mapped_fields: Vec<SMBField<Field>> = match structure.fields {
        Fields::Named(ref fields) => SMBField::from_iter(fields.named.iter())?,
        Fields::Unnamed(ref fields) => SMBField::from_iter(fields.unnamed.iter())?,
        Fields::Unit => vec![],
    };

    mapped_fields.sort();

    let mapping_type = match structure.fields {
        Fields::Named(_) => SMBFieldMappingType::NamedStruct,
        Fields::Unnamed(_) => SMBFieldMappingType::UnnamedStruct,
        Fields::Unit => SMBFieldMappingType::Unit
    };

    let spanned_field = &structure.fields;

    let usize_ty = Type::Path(TypePath {
        qself: None,
        path: Path::from(Ident::new("usize", spanned_field.span())),
    });

    let mut punctuated_bracket_arg: Punctuated<GenericArgument, Token![,]> = Punctuated::new();

    punctuated_bracket_arg.push(GenericArgument::Type(usize_ty));

    let path_segments = [
        PathSegment::from(Ident::new("std", spanned_field.span())),
        PathSegment::from(Ident::new("marker", spanned_field.span())),
        PathSegment {
            ident: Ident::new("PhantomData", spanned_field.span()),
            arguments: PathArguments::AngleBracketed(AngleBracketedGenericArguments {
                colon2_token: None,
                lt_token: Default::default(),
                args: punctuated_bracket_arg,
                gt_token: Default::default(),
            }),
        },
    ];

    let segments: Punctuated<PathSegment, Token![::]> = Punctuated::from_iter(path_segments);

    let phantom_data_path = Path {
        leading_colon: Some(PathSep::default()),
        segments,
    };

    let phantom_ty = Type::Path(TypePath {
        qself: None,
        path: phantom_data_path,
    });

    let parent = SMBField::new(spanned_field, format_ident!("structure_base"), phantom_ty, parent_attrs);

    Ok(SMBFieldMapping {
        parent,
        fields: mapped_fields,
        mapping_type,
    })
}


pub(crate) fn smb_from_bytes<T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq>(mapping: &SMBFieldMapping<T, U>) -> proc_macro2::TokenStream {
    let vector = &mapping.fields;
    let recurse = vector.iter().map(SMBField::smb_from_bytes);
    let parent = mapping.parent.smb_from_bytes();
    let names = vector.iter().map(SMBField::get_name);

    let expanded_stream = match mapping.mapping_type {
        SMBFieldMappingType::NamedStruct => {
            quote! {
                #(#recurse)*
                println!("Size: {}", current_pos);
                Ok((remaining, Self {
                    #(#names,)*
                }))
            }
        }
        SMBFieldMappingType::UnnamedStruct => {
            quote! {
                #(#recurse)*
                Ok((remaining, Self (
                    #(#names,)*
                )))
            }
        }
        SMBFieldMappingType::Enum => {
            quote! {
                #(#recurse)*
                let value = Self::try_from(#(#names)*).map_err(|_e| ::smb_core::error::SMBError::ParseError("Invalid primitive value"))?;
                Ok((remaining, value))
            }
        }
        SMBFieldMappingType::Unit => {
            quote! {
                Ok((remaining, Self))
            }
        }
    };

    quote! {
        let mut current_pos = 0;
        let remaining = input;
        #parent
        #expanded_stream
    }
}

pub(crate) fn smb_to_bytes<T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq>(mapping: &SMBFieldMapping<T, U>) -> proc_macro2::TokenStream {
    let vector = &mapping.fields;
    let parent = match mapping.mapping_type {
        SMBFieldMappingType::Enum => mapping.parent.smb_to_bytes_enum(),
        _ => mapping.parent.smb_to_bytes_struct()
    };

    let recurse = match mapping.mapping_type {
        SMBFieldMappingType::Enum => vector.iter().map(SMBField::smb_to_bytes_enum).collect::<Vec<proc_macro2::TokenStream>>(),
        _ => vector.iter().map(SMBField::smb_to_bytes_struct).collect()
    };

    quote! {
        let mut current_pos = 0;
        let mut item = vec![0; ::smb_core::SMBByteSize::smb_byte_size(self)];
        #parent
        #(#recurse)*
        item
    }
}