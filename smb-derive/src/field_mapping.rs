use std::fmt::Debug;

use darling::FromAttributes;
use proc_macro2::Ident;
use quote::{format_ident, quote, quote_spanned};
use syn::{AngleBracketedGenericArguments, Attribute, DataEnum, DeriveInput, Field, Fields, GenericArgument, Path, PathArguments, PathSegment, Token, Type, TypePath};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::token::PathSep;

use crate::attrs::{AttributeInfo, Direct, Discriminator, Repr};
use crate::field::{SMBField, SMBFieldType};
use crate::SMBDeriveError;

#[derive(Debug, PartialEq, Eq)]
pub struct SMBFieldMapping<'a, T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq> {
    parent: SMBField<'a, T>,
    fields: Vec<SMBField<'a, U>>,
    mapping_type: SMBFieldMappingType,
    discriminators: Vec<u64>,
    variant_ident: Option<Ident>
}

#[derive(Debug, PartialEq, Eq)]
pub enum SMBFieldMappingType {
    NamedStruct,
    UnnamedStruct,
    NumEnum,
    DiscriminatedEnum,
    Unit,
}

impl<T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq + Debug> SMBFieldMapping<'_, T, U> {
    pub(crate) fn get_mapping_size(&self) -> proc_macro2::TokenStream {
        let parent_size = self.parent.attr_byte_size();
        let variant = self.variant_ident.is_some();
        let size = match &self.mapping_type {
            SMBFieldMappingType::NamedStruct => self.fields.iter().map(|f| {
                let token = match variant {
                    true => f.get_name(),
                    false => f.get_named_token(),
                };
                let size = f.get_smb_message_size(token.clone());
                println!("token: {}, size: {}", token, size);
                size
            }).collect(),
            SMBFieldMappingType::UnnamedStruct => self.fields.iter().enumerate().map(|(idx, f)| {
                let token = match variant {
                    true => f.get_name(),
                    false => f.get_unnamed_token(idx),
                };
                f.get_smb_message_size(token)
            }).collect(),
            SMBFieldMappingType::NumEnum => self.fields.iter().map(|f| {
                let token = match variant {
                    true => f.get_name(),
                    false => f.get_num_enum_token(),
                };
                f.get_smb_message_size(token)
            }).collect(),
            SMBFieldMappingType::DiscriminatedEnum => self.fields.iter().map(|f| {
                let token = match variant {
                    true => f.get_name(),
                    false => f.get_disc_enum_token(),
                };
                f.get_smb_message_size(token)
            }).collect(),
            SMBFieldMappingType::Unit => vec![quote! {

            }]
        };

        let names = self.fields.iter().map(|field| field.get_name());
        let key = self.variant_ident.clone().map(|variant| quote! {
            Self::#variant(#(#names,)*)
        }).unwrap_or(quote! {_});

        quote! {
            #key => {
                let size = #parent_size;
                #(#size)*
                size
            },
        }
    }
}

pub(crate) fn enum_repr_type(attrs: &[Attribute]) -> darling::Result<Repr> {
    return Repr::from_attributes(attrs)
}

pub(crate) fn get_num_enum_mapping(input: &DeriveInput, parent_attrs: Vec<SMBFieldType>, repr_type: Repr) -> Result<SMBFieldMapping<DeriveInput, DeriveInput>, SMBDeriveError<DeriveInput>> {
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
            start: AttributeInfo::Fixed(0),
            order: 0,
        })],
    );
    let parent = SMBField::new(input, format_ident!("enum_outer"), ty, parent_attrs);
    Ok(SMBFieldMapping {
        parent,
        fields: vec![smb_field],
        mapping_type: SMBFieldMappingType::NumEnum,
        discriminators: vec![],
        variant_ident: None,
    })
}

pub(crate) fn get_desc_enum_mapping(info: &DataEnum) -> Result<Vec<SMBFieldMapping<Fields, Field>>, SMBDeriveError<Field>> {
    info.variants.iter().map(|variant| {
        println!("attrs: {:?}", variant.attrs);
        let discriminators = Discriminator::from_attributes(&variant.attrs).map(|d| d.values.iter().map(|val| val | d.flag).collect())
            .map_err(|_e| SMBDeriveError::MissingField)?;

        println!("Discs: {:?}", discriminators);
        get_struct_field_mapping(&variant.fields, vec![SMBFieldType::from_attributes(&variant.attrs).unwrap()], discriminators, Some(variant.ident.clone()))
    }).collect()
}

pub(crate) fn get_struct_field_mapping(struct_fields: &Fields, parent_attrs: Vec<SMBFieldType>, discriminators: Vec<u64>, variant_ident: Option<Ident>) -> Result<SMBFieldMapping<Fields, Field>, SMBDeriveError<Field>> {
    if struct_fields.len() == 1 {
        let field = struct_fields.iter().next()
            .ok_or(SMBDeriveError::InvalidType)?;
        let (field, val_types) = if !parent_attrs.is_empty() {
            (field, parent_attrs)
        } else {
            (field, vec![SMBFieldType::Direct(Direct {
                start: AttributeInfo::Fixed(0),
                order: 0,
            })])
        };

        let name = if let Some(x) = &field.ident {
            x.clone()
        } else {
            format_ident!("val_0")
        };


        let fields = vec![SMBField::new(field, name, field.ty.clone(), val_types)];

        let parent = SMBField::new(struct_fields, format_ident!("single_base"), field.ty.clone(), vec![]);

        return if field.ident.is_some() {
            Ok(SMBFieldMapping {
                parent,
                fields,
                mapping_type: SMBFieldMappingType::NamedStruct,
                discriminators,
                variant_ident
            })
        } else {
            Ok(SMBFieldMapping {
                parent,
                fields,
                mapping_type: SMBFieldMappingType::UnnamedStruct,
                discriminators,
                variant_ident
            })
        };
    }
    let mut mapped_fields: Vec<SMBField<Field>> = match struct_fields {
        Fields::Named(ref fields) => SMBField::from_iter(fields.named.iter())?,
        Fields::Unnamed(ref fields) => SMBField::from_iter(fields.unnamed.iter())?,
        Fields::Unit => vec![],
    };

    mapped_fields.sort();

    let mapping_type = match struct_fields {
        Fields::Named(_) => SMBFieldMappingType::NamedStruct,
        Fields::Unnamed(_) => SMBFieldMappingType::UnnamedStruct,
        Fields::Unit => SMBFieldMappingType::Unit
    };

    let spanned_field = struct_fields;

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
        discriminators,
        variant_ident
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
        SMBFieldMappingType::NumEnum => {
            quote! {
                #(#recurse)*
                let vals = #(#names)*;
                let value = Self::try_from(vals).map_err(|_e| ::smb_core::error::SMBError::parse_error("Invalid primitive value"))?;
                Ok((remaining, value))
            }
        },
        SMBFieldMappingType::DiscriminatedEnum => {
            quote! {}
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

pub(crate) fn smb_enum_from_bytes<T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq>(mapping: &SMBFieldMapping<T, U>) -> proc_macro2::TokenStream {
    let vector = &mapping.fields;
    let recurse = vector.iter().map(SMBField::smb_from_bytes);
    let parent = mapping.parent.smb_from_bytes();
    let names = vector.iter().map(SMBField::get_name);
    if mapping.variant_ident.is_none() {
        return quote_spanned! {mapping.parent.spanned().span() =>
            std::compile_error!("No variant identifier provided for enum field")
        }
    }
    let variant_ident = &mapping.variant_ident.clone().unwrap();

    let expanded_stream = match mapping.mapping_type {
        SMBFieldMappingType::UnnamedStruct => {
            quote! {
                #(#recurse)*
                Ok((remaining, Self::#variant_ident(
                    #(#names,)*
                )))
            }
        },
        SMBFieldMappingType::NamedStruct => {
            quote! {
                #(#recurse)*
                Ok((remaining, Self::variant_ident{
                    #(#names,)*
                }))
            }
        },
        _ => panic!("Only enums with associated types can be used to derive SMBEnumFromBytes, please use SMBFromBytes for other types")
    };

    let tokens = quote! {
        {
            let mut current_pos = 0;
            let remaining = input;
            #parent
            #expanded_stream
        }
    };

    let recursive_mapping = mapping.discriminators.iter().map(|discriminator| quote! {
        #discriminator => #tokens,
    });

    quote! {
        #(#recursive_mapping)*
    }
}

pub(crate) fn smb_to_bytes<T: Spanned + PartialEq + Eq, U: Spanned + PartialEq + Eq>(mapping: &SMBFieldMapping<T, U>) -> proc_macro2::TokenStream {
    let vector = &mapping.fields;
    let variant = mapping.variant_ident.is_some();
    let parent = match mapping.mapping_type {
        SMBFieldMappingType::NumEnum => mapping.parent.smb_to_bytes_enum(),
        _ => mapping.parent.smb_to_bytes_struct(variant)
    };

    let recurse = match mapping.mapping_type {
        SMBFieldMappingType::NumEnum => vector.iter().map(SMBField::smb_to_bytes_enum).collect::<Vec<proc_macro2::TokenStream>>(),
        _ => vector.iter().map(|field| field.smb_to_bytes_struct(variant)).collect()
    };

    let names = mapping.fields.iter().map(|field| field.get_name());

    let key = mapping.variant_ident.clone().map(|variant| quote! {
        Self::#variant(#(#names,)*)
    }).unwrap_or(quote! {_});
    quote! {
        #key => {
            let mut current_pos = 0;
            let mut item = vec![0; ::smb_core::SMBByteSize::smb_byte_size(self)];
            #parent
            #(#recurse)*
            item
        },
    }
}