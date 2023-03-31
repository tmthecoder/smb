use std::fmt::Debug;

use proc_macro2::Ident;
use quote::{format_ident, quote};
use syn::{Attribute, DataStruct, DeriveInput, Field, Fields, Path, Type, TypePath};
use syn::spanned::Spanned;

use crate::attrs::{Direct, Repr};
use crate::field::{SMBField, SMBFieldType};
use crate::SMBDeriveError;

#[derive(Debug, PartialEq, Eq)]
pub struct SMBFieldMapping<'a, T: Spanned + PartialEq + Eq> {
    fields: Vec<SMBField<'a, T>>,
    mapping_type: SMBFieldMappingType,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SMBFieldMappingType {
    NamedStruct,
    UnnamedStruct,
    Enum,
    Unit,
}

impl<T: Spanned + PartialEq + Eq + Debug> SMBFieldMapping<'_, T> {
    pub(crate) fn get_mapping_size(&self) -> proc_macro2::TokenStream {
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
                std::compile_error!("Invalid structure type")
            }]
        };

        quote! {
            0 #(+ #size)*
        }
    }
}

pub(crate) fn get_enum_field_mapping<'a>(enum_attributes: &[Attribute], input: &'a DeriveInput) -> Result<SMBFieldMapping<'a, DeriveInput>, SMBDeriveError<DeriveInput>> {
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
        ty,
        SMBFieldType::Direct(Direct {
            start: 0
        }),
    );
    Ok(SMBFieldMapping {
        fields: vec![smb_field],
        mapping_type: SMBFieldMappingType::Enum,
    })
}

pub(crate) fn get_struct_field_mapping(structure: &DataStruct, parent_val_type: Option<SMBFieldType>) -> Result<SMBFieldMapping<Field>, SMBDeriveError<Field>> {
    if structure.fields.len() == 1 {
        let field = structure.fields.iter().next()
            .ok_or(SMBDeriveError::InvalidType)?;
        let (field, val_type) = if let Some(parent) = parent_val_type {
            (field, parent)
        } else {
            (field, SMBFieldType::Direct(Direct {
                start: 0,
            }))
        };

        let name = if let Some(x) = &field.ident {
            x.clone()
        } else {
            format_ident!("val_0")
        };


        let fields = vec![SMBField::new(field, name, field.ty.clone(), val_type)];

        return if field.ident.is_some() {
            Ok(SMBFieldMapping {
                fields,
                mapping_type: SMBFieldMappingType::NamedStruct,
            })
        } else {
            Ok(SMBFieldMapping {
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

    Ok(SMBFieldMapping {
        fields: mapped_fields,
        mapping_type,
    })
}


pub(crate) fn parse_smb_message<T: Spanned + PartialEq + Eq + Debug>(mapping: &SMBFieldMapping<T>) -> proc_macro2::TokenStream {
    let vector = &mapping.fields;
    let recurse = vector.iter().map(SMBField::get_smb_message_info);

    let names = vector.iter().map(SMBField::get_name);

    let expanded_stream = match mapping.mapping_type {
        SMBFieldMappingType::NamedStruct => {
            quote! {
                #(#recurse)*
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
                std::compile_error!("Invalid struct type")
            }
        }
    };
    quote! {
        let mut current_pos = 0;
        let remaining = input;
        #expanded_stream
    }
}