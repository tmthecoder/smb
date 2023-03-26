extern crate proc_macro;

use proc_macro::TokenStream;
use std::cmp::{min, Ordering};
use std::fmt::{Display, Formatter};

use darling::{FromDeriveInput, FromField};
use proc_macro2::Ident;
use quote::{format_ident, quote, quote_spanned};
use syn::{Data, DataStruct, DeriveInput, Field, Fields, parse_macro_input};
use syn::spanned::Spanned;

use crate::attrs::{Buffer, Direct, Repr};

mod attrs;

#[derive(Debug, PartialEq, Eq)]
enum SMBFieldMapping<'a> {
    Named(Vec<SMBField<'a>>),
    Unnamed(Vec<SMBField<'a>>),
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
}

impl PartialOrd for SMBFieldType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.find_start_val().cmp(&other.find_start_val()))
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
        self.find_start_val().cmp(&other.find_start_val())
    }
}

impl SMBFieldType {
    fn find_start_val(&self) -> usize {
        match self {
            Self::Direct(x) => x.start,
            Self::Buffer(x) => min(x.length.start, x.offset.start)
        }
    }
}

#[proc_macro_derive(SMBFromBytes, attributes(direct, buffer, byte_tag, string_tag))]
pub fn smb_from_bytes(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);

    // println!("attrs: {:?}", input.attrs);

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
            println!("repr: {:?}", repr_type);
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
                    }
                }.into();
                println!("quote: {:?}", quote.to_string());
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

    let parser = create_parser(&mapped.unwrap());

    println!("Parser: {:?}", parser.to_string());

    let tokens = quote! {
        impl ::smb_core::SMBFromBytes for #name {
            fn parse_smb_message(_input: &[u8]) -> ::smb_core::SMBResult<&[u8], Self, ::smb_core::error::SMBError> {
                #parser
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

        let vec = vec![SMBField {
            name,
            field,
            val_type,
        }];

        return if field.ident.is_some() {
            Ok(SMBFieldMapping::Named(vec))
        } else {
            Ok(SMBFieldMapping::Unnamed(vec))
        }
    }

    let mut mapped_fields: Vec<SMBField> = match structure.fields {
        Fields::Named(ref fields) => map_to_smb_field(fields.named.iter())?,
        Fields::Unnamed(ref fields) => map_to_smb_field(fields.unnamed.iter())?,
        Fields::Unit => vec![],
    };

    mapped_fields.sort();

    let mapping = match structure.fields {
        Fields::Named(_) => SMBFieldMapping::Named(mapped_fields),
        Fields::Unnamed(_) => SMBFieldMapping::Unnamed(mapped_fields),
        Fields::Unit => SMBFieldMapping::Unit
    };

    Ok(mapping)
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

fn create_parser(mapping: &SMBFieldMapping) -> proc_macro2::TokenStream {
    let empty = vec![];

    let vector = match mapping {
        SMBFieldMapping::Named(vector) => vector,
        SMBFieldMapping::Unnamed(vector) => vector,
        SMBFieldMapping::Unit => &empty,
    };

    let recurse = vector.iter().map(|f| {
        let name = &f.name;
        let field = f.field;
        let ty = &f.field.ty;
        match &f.val_type {
            SMBFieldType::Direct(direct) => {
                let start = direct.start;
                let name_end = format_ident!("{}_end", name);
                quote_spanned! { field.span() =>
                    let #name_end = #start + std::mem::size_of::<#ty>();
                    let (_, #name) = <#ty>::parse_smb_message(&_input[#start..#name_end])?;
                    ending = std::cmp::max(#name_end, ending);
                }
            },
            SMBFieldType::Buffer(buffer) => {
                let offset_start = buffer.offset.start;
                let offset_type = &buffer.offset.ty;
                let length_start = buffer.length.start;
                let length_type = &buffer.length.ty;

                quote_spanned! {field.span() =>
                    let offset_end = #offset_start + <#offset_type>::smb_byte_size();
                    let length_end = #length_start + <#length_type>::smb_byte_size();
                    let offset = u32::parse_smb_message(&_input[#offset_start..offset_end])?;
                    let length = u32::parse_smb_message(&_input[#length_start..length_end])?;
                    let #name = _input[(offset as usize)..(offset as usize + length as usize)].to_vec();
                    ending = std::cmp::max(offset as usize + length as usize, ending);
                }
            }
        }
    });

    let names = vector.iter().map(|f| {
        let name = &f.name;
        let field = f.field;
        quote_spanned! {field.span() => #name}
    });

    match mapping {
        SMBFieldMapping::Named(_) => {
            quote! {
                let mut ending = 0_usize;
                #(#recurse)*
                Ok((&_input[ending..], Self {
                    #(#names,)*
                }))
            }
        },
        SMBFieldMapping::Unnamed(_) => {
            quote! {
                #(#recurse)*
                Ok(Self (
                    #(#names,)*
                ))
            }
        },
        SMBFieldMapping::Unit => {
            quote! {
                std::compile_error!("Invalid struct type")
            }
        }
    }
}

fn get_value_type(field: &Field) -> Result<SMBFieldType, SMBDeriveError> {
    if let Ok(buffer) = Buffer::from_field(field) {
        Ok(SMBFieldType::Buffer(buffer))
    } else if let Ok(direct) = Direct::from_field(field) {
        Ok(SMBFieldType::Direct(direct))
    } else {
        Err(SMBDeriveError::TypeError(field.clone()))
    }
}

fn parent_value_type(input: &DeriveInput) -> Option<SMBFieldType> {
    if let Ok(buffer) = Buffer::from_derive_input(input) {
        Some(SMBFieldType::Buffer(buffer))
    } else if let Ok(direct) = Direct::from_derive_input(input) {
        Some(SMBFieldType::Direct(direct))
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