extern crate proc_macro;

use proc_macro::TokenStream;
use std::cmp::{min, Ordering};
use std::fmt::{Display, Formatter};

use darling::{FromDeriveInput, FromField};
use proc_macro2::Ident;
use quote::{format_ident, quote, quote_spanned};
use syn::{Data, DataStruct, DeriveInput, Field, Fields, parse_macro_input};
use syn::spanned::Spanned;

use crate::attrs::{Buffer, Direct, Repr, Skip, Vector};

mod attrs;

#[derive(Debug, PartialEq, Eq)]
struct SMBFieldMapping<'a> {
    fields: Vec<SMBField<'a>>,
    mapping_type: SMBFieldMappingType,
}

#[derive(Debug, PartialEq, Eq)]
enum SMBFieldMappingType {
    Named,
    Unnamed,
    Unit,
}

#[derive(Debug, PartialEq, Eq)]
struct SMBField<'a> {
    field: &'a Field,
    name: Ident,
    val_type: SMBFieldType,
}

#[derive(Debug, PartialEq, Eq)]
enum SMBFieldType {
    Direct(Direct),
    Buffer(Buffer),
    Vector(Vector),
    Skip(Skip)
}

impl SMBFieldType {
    fn is_vector(&self) -> bool {
        matches!(self, SMBFieldType::Vector(_x))
    }
}

impl PartialOrd for SMBFieldType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.is_vector() && !other.is_vector() {
            Some(Ordering::Greater)
        } else if !self.is_vector() && other.is_vector() {
            Some(Ordering::Less)
        } else {
            Some(self.find_start_val().cmp(&other.find_start_val()))
        }
    }
}

impl<'a> PartialOrd for SMBField<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.val_type.partial_cmp(&other.val_type)
    }
}

impl<'a> Ord for SMBField<'a> {
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
}

#[proc_macro_derive(SMBFromBytes, attributes(direct, buffer, vector, skip, byte_tag, string_tag))]
pub fn smb_from_bytes(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);

    let name = input.ident.clone();

    let invalid_token: TokenStream = quote_spanned! {
        input.span() => compile_error!("Invalid or unsupported type")
    }.into();

    let mapped = match &input.data {
        Data::Struct(structure) => {
            let parent_val_type = parent_value_type(&input);
            get_field_mapping(structure, parent_val_type)
        },
        Data::Enum(_en) => {
            let repr_type = Repr::from_derive_input(&input);
            if let Ok(ty) = repr_type {
                let identity = &ty.ident;
                let quote: TokenStream = quote! {
                    impl ::smb_core::SMBFromBytes for #name {
                        fn parse_smb_message(_input: &[u8]) -> ::smb_core::SMBResult<&[u8], Self, ::smb_core::error::SMBError> {
                            let (remaining, repr_val) = <#identity>::parse_smb_message(_input)?;
                            let value = Self::try_from(repr_val)
                                .map_err(|_e| ::smb_core::error::SMBError::ParseError("Invalid byte slice".into()))?;
                            Ok((remaining, value))
                        }
                        fn smb_byte_size(&self) -> usize {
                            ::std::mem::size_of_val(self)
                        }
                    }
                }.into();
                return quote;
            }
            return invalid_token
        },
        _ => return invalid_token
    };

    if let Err(e) = mapped {
        return match e {
            SMBDeriveError::TypeError(f) => {
                quote_spanned! {
                    f.span() => std::compile_error!("No type set or incorrectly defined type for field")
                }
            },
            SMBDeriveError::InvalidType => {
                quote_spanned! {
                    input.span() => std::compile_error!("Invalid or unsupported type")
                }
            }
        }.into()
    }

    let mapped = mapped.unwrap();

    let parser = parse_smb_message(&mapped);

    let size = smb_byte_size(&mapped);

    let tokens = quote! {
        impl ::smb_core::SMBFromBytes for #name {
            #[allow(unused_variables, unused_assignments)]
            fn parse_smb_message(input: &[u8]) -> ::smb_core::SMBResult<&[u8], Self, ::smb_core::error::SMBError> {
                #parser
            }
            fn smb_byte_size(&self) -> usize {
                #size
            }
        }
    };

    tokens.into()
}

fn get_field_mapping(structure: &DataStruct, parent_val_type: Option<SMBFieldType>) -> Result<SMBFieldMapping, SMBDeriveError> {
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

        let fields = vec![SMBField {
            name,
            field,
            val_type,
        }];

        return if field.ident.is_some() {
            Ok(SMBFieldMapping {
                fields,
                mapping_type: SMBFieldMappingType::Named,
            })
        } else {
            Ok(SMBFieldMapping {
                fields,
                mapping_type: SMBFieldMappingType::Unnamed,
            })
        }
    }

    let mut mapped_fields: Vec<SMBField> = match structure.fields {
        Fields::Named(ref fields) => map_to_smb_field(fields.named.iter())?,
        Fields::Unnamed(ref fields) => map_to_smb_field(fields.unnamed.iter())?,
        Fields::Unit => vec![],
    };

    mapped_fields.sort();

    let mapping_type = match structure.fields {
        Fields::Named(_) => SMBFieldMappingType::Named,
        Fields::Unnamed(_) => SMBFieldMappingType::Unnamed,
        Fields::Unit => SMBFieldMappingType::Unit
    };

    Ok(SMBFieldMapping {
        fields: mapped_fields,
        mapping_type,
    })
}

fn map_to_smb_field<'a, T: Iterator<Item=&'a Field>>(fields: T) -> Result<Vec<SMBField<'a>>, SMBDeriveError> {
    fields.enumerate().map(|(idx, field)| {
        let val_type = get_value_type(field)?;
        let name = if let Some(x) = &field.ident {
            x.clone()
        } else {
            format_ident!("val_{}", idx)
        };
        Ok(SMBField {
            name,
            field,
            val_type,
        })
    }).collect::<Vec<Result<SMBField, SMBDeriveError>>>()
        .into_iter()
        .collect::<Result<Vec<SMBField>, SMBDeriveError>>()
}

fn parse_smb_message(mapping: &SMBFieldMapping) -> proc_macro2::TokenStream {
    let vector = &mapping.fields;
    let recurse = vector.iter().map(|f| {
        let name = &f.name;
        let field = f.field;
        let ty = &f.field.ty;
        match &f.val_type {
            SMBFieldType::Direct(direct) => {
                let start = direct.start;
                quote_spanned! { field.span() =>
                    let (remaining, #name) = <#ty>::parse_smb_message(&remaining[(#start - current_pos)..])?;
                    current_pos = #name.smb_byte_size() + #start;
                }
            },
            SMBFieldType::Buffer(buffer) => {
                let offset_start = buffer.offset.start;
                let offset_type = format_ident!("{}", &buffer.offset.ty);

                let offset_block = if &buffer.offset.ty != "direct" {
                    quote! {
                        let (remaining, offset) = <#offset_type>::parse_smb_message(&input[#offset_start..])?;
                        current_pos = offset.smb_byte_size() + #offset_start;
                    }
                } else {
                    quote! {
                        let offset = current_pos;
                    }
                };

                let length_start = buffer.length.start;
                let length_type = format_ident!("{}", &buffer.length.ty);

                quote_spanned! { field.span() =>
                    // let (remaining, offset) = <#offset_type>::parse_smb_message(&remaining[(#offset_start - current_pos)..])?;
                    // current_pos = offset.smb_byte_size() + #offset_start;
                    let (remaining, length) = <#length_type>::parse_smb_message(&input[#length_start..])?;
                    current_pos = length.smb_byte_size() + #length_start;
                    #offset_block
                    let buf_end = offset as usize + length as usize;
                    let #name = input[(offset as usize)..].to_vec();
                    let remaining = &input[buf_end..];
                }
            },
            SMBFieldType::Vector(vector) => {
                let count_start = vector.count.start;
                let count_type = format_ident!("{}", &vector.count.ty);
                let align = vector.align;
                let inner_type = &f.field.ty;


                quote_spanned! { field.span() =>
                    let (remaining, item_count) = <#count_type>::parse_smb_message(&input[#count_start..])?;
                    if #align > 0 && current_pos % #align != 0 {
                        current_pos += 8 - (current_pos % #align);
                    }
                    let mut remaining = &input[current_pos..];
                    let #name: #inner_type = (0..item_count).map(|idx| {
                        let (r, val) = <#inner_type>::parse_smb_message(remaining)?;
                        current_pos += val.smb_byte_size();
                        remaining = r;
                        Ok(val)
                    }).collect::<Vec<Result<#inner_type, ::smb_core::error::SMBError>>>().into_iter().collect::<Result<Vec<#inner_type>, ::smb_core::error::SMBError>>()?
                        .iter_mut().map(|v| v.remove(0)).collect::<#inner_type>();
                }
            },
            SMBFieldType::Skip(skip) => {
                let start = skip.start;
                let length = skip.length;

                quote_spanned! {field.span() =>
                    current_pos = #start + #length;
                    let remaining = &input[current_pos..];
                    let #name = ::std::marker::PhantomData;
                }
            }
        }
    });

    let names = vector.iter().map(|f| {
        let name = &f.name;
        let field = f.field;
        quote_spanned! {field.span() => #name}
    });

    let expanded_stream = match mapping.mapping_type {
        SMBFieldMappingType::Named => {
            quote! {
                #(#recurse)*
                Ok((remaining, Self {
                    #(#names,)*
                }))
            }
        },
        SMBFieldMappingType::Unnamed => {
            quote! {
                #(#recurse)*
                Ok((remaining, Self (
                    #(#names,)*
                )))
            }
        },
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

fn smb_byte_size(mapping: &SMBFieldMapping) -> proc_macro2::TokenStream {
    let idents = match mapping.mapping_type {
        SMBFieldMappingType::Named => mapping.fields.iter().map(|f| (f, f.name.clone())).collect(),
        SMBFieldMappingType::Unnamed => mapping.fields.iter().enumerate().map(|(idx, f)| (f, format_ident!("{}", idx))).collect(),
        SMBFieldMappingType::Unit => vec![]
    };

    let size = idents.into_iter().map(|(field, name)| {
        quote_spanned! {field.field.span() =>
            ::smb_core::SMBFromBytes::smb_byte_size(&self.#name)
        }
    });

    quote! {
        0 #(+ #size)*
    }
}

fn get_value_type(field: &Field) -> Result<SMBFieldType, SMBDeriveError> {
    if let Ok(buffer) = Buffer::from_field(field) {
        Ok(SMBFieldType::Buffer(buffer))
    } else if let Ok(direct) = Direct::from_field(field) {
        Ok(SMBFieldType::Direct(direct))
    } else if let Ok(vector) = Vector::from_field(field) {
        Ok(SMBFieldType::Vector(vector))
    } else if let Ok(skip) = Skip::from_field(field) {
        Ok(SMBFieldType::Skip(skip))
    } else {
        Err(SMBDeriveError::TypeError(field.clone()))
    }
}

fn parent_value_type(input: &DeriveInput) -> Option<SMBFieldType> {
    if let Ok(buffer) = Buffer::from_derive_input(input) {
        Some(SMBFieldType::Buffer(buffer))
    } else if let Ok(direct) = Direct::from_derive_input(input) {
        Some(SMBFieldType::Direct(direct))
    } else if let Ok(vector) = Vector::from_derive_input(input) {
        Some(SMBFieldType::Vector(vector))
    } else {
        None
    }
}

#[derive(Debug)]
enum SMBDeriveError {
    TypeError(Field),
    InvalidType,
}

impl Display for SMBDeriveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TypeError(field) => write!(f, "No type annotation for field ${:?} (must be buffer or direct)", field.ident),
            Self::InvalidType => write!(f, "Unsupported or invalid type"),
        }
    }
}

impl std::error::Error for SMBDeriveError {}

#[proc_macro_derive(SMBToBytes)]
pub fn smb_to_bytes(_input: TokenStream) -> TokenStream {
    _input
}