extern crate proc_macro;

use proc_macro::TokenStream;
use std::cmp::{min, Ordering};
use std::fmt::{Debug, Display, Formatter};

use darling::{FromDeriveInput, FromField};
use proc_macro2::Ident;
use quote::{format_ident, quote, quote_spanned};
use syn::{Attribute, Data, DataStruct, DeriveInput, Field, Fields, parse_macro_input, Type};
use syn::spanned::Spanned;

use crate::attrs::{Buffer, Direct, Repr, Skip, Vector};

mod attrs;

#[derive(Debug, PartialEq, Eq)]
struct SMBFieldMapping<'a, T: Spanned + PartialEq + Eq> {
    fields: Vec<SMBField<'a, T>>,
    mapping_type: SMBFieldMappingType,
}

#[derive(Debug, PartialEq, Eq)]
enum SMBFieldMappingType {
    NamedStruct,
    UnnamedStruct,
    Enum,
    Unit,
}

#[derive(Debug, PartialEq, Eq)]
struct SMBField<'a, T: Spanned> {
    spannable: &'a T,
    name: Ident,
    ty: Type,
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

#[proc_macro_derive(SMBFromBytes, attributes(direct, buffer, vector, skip, byte_tag, string_tag))]
pub fn smb_from_bytes(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);

    let name = &input.ident;

    let invalid_token: proc_macro2::TokenStream = quote_spanned! {
        input.span() => compile_error!("Invalid or unsupported type")
    };

    let parse_token = match &input.data {
        Data::Struct(structure) => {
            let parent_val_type = parent_value_type(&input);
            let mapping = get_struct_field_mapping(structure, parent_val_type);
            create_parser_impl(mapping, name)
                .unwrap_or_else(|e| match e {
                    SMBDeriveError::TypeError(f) => quote_spanned! {f.span()=>::std::compile_error!("Invalid field for SMB message parsing")},
                    SMBDeriveError::InvalidType => invalid_token
                })
        },
        Data::Enum(_en) => {
            let mapping = get_enum_field_mapping(&input.attrs, &input);
            create_parser_impl(mapping, name)
                .unwrap_or_else(|_e| quote_spanned! {input.span()=>
                    ::std::compile_error!("Invalid enum for SMB message parsing")
                })
        },
        _ => invalid_token
    };

    parse_token.into()
}

fn get_struct_field_mapping(structure: &DataStruct, parent_val_type: Option<SMBFieldType>) -> Result<SMBFieldMapping<Field>, SMBDeriveError<Field>> {
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
            spannable: field,
            ty: field.ty.clone(),
            val_type,
        }];

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
        }
    }

    let mut mapped_fields: Vec<SMBField<Field>> = match structure.fields {
        Fields::Named(ref fields) => map_to_smb_field(fields.named.iter())?,
        Fields::Unnamed(ref fields) => map_to_smb_field(fields.unnamed.iter())?,
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

fn get_enum_field_mapping<'a>(enum_attributes: &[Attribute], input: &'a DeriveInput) -> Result<SMBFieldMapping<'a, DeriveInput>, SMBDeriveError<DeriveInput>> {
    let repr_type = Repr::from_attributes(enum_attributes)
        .map_err(|_e| SMBDeriveError::TypeError(input.clone()))?;
    let identity = &repr_type.ident;
    let ty = syn::parse_str::<Type>(&quote! {core::primitive::#identity}.to_string())
        .map_err(|_e| SMBDeriveError::TypeError(input.clone()))?;
    let smb_field = SMBField {
        spannable: input,
        name: format_ident!("enum_field"),
        ty,
        val_type: SMBFieldType::Direct(Direct {
            start: 0
        }),
    };
    Ok(SMBFieldMapping {
        fields: vec![smb_field],
        mapping_type: SMBFieldMappingType::Enum,
    })
}

fn map_to_smb_field<'a, T: Iterator<Item=&'a Field>>(fields: T) -> Result<Vec<SMBField<'a, Field>>, SMBDeriveError<Field>> {
    fields.enumerate().map(|(idx, field)| {
        let val_type = get_value_type(field)?;
        let name = if let Some(x) = &field.ident {
            x.clone()
        } else {
            format_ident!("val_{}", idx)
        };
        Ok(SMBField {
            name,
            spannable: field,
            ty: field.ty.clone(),
            val_type,
        })
    }).collect::<Vec<Result<SMBField<Field>, SMBDeriveError<Field>>>>()
        .into_iter()
        .collect::<Result<Vec<SMBField<Field>>, SMBDeriveError<Field>>>()
}

fn create_parser_impl<T: Spanned + PartialEq + Eq + Debug>(mapping: Result<SMBFieldMapping<T>, SMBDeriveError<T>>, name: &Ident) -> Result<proc_macro2::TokenStream, SMBDeriveError<T>> {
    let mapping = mapping?;
    let parser = parse_smb_message(&mapping);
    let size = smb_byte_size(&mapping);

    Ok(quote! {
        impl ::smb_core::SMBFromBytes for #name {
            #[allow(unused_variables, unused_assignments)]
            fn parse_smb_message(input: &[u8]) -> ::smb_core::SMBResult<&[u8], Self, ::smb_core::error::SMBError> {
                #parser
            }
            fn smb_byte_size(&self) -> usize {
                #size
            }
        }
    })
}

fn parse_smb_message<T: Spanned + PartialEq + Eq>(mapping: &SMBFieldMapping<T>) -> proc_macro2::TokenStream {
    let vector = &mapping.fields;
    let recurse = vector.iter().map(|f| {
        let name = &f.name;
        let field = f.spannable;
        let ty = &f.ty;
        match &f.val_type {
            SMBFieldType::Direct(direct) => {
                let start = direct.start;
                quote_spanned! { field.span() =>
                    let (remaining, #name) = <#ty>::parse_smb_message(&input[#start..])?;
                    current_pos = #name.smb_byte_size() + #start;
                }
            },
            SMBFieldType::Buffer(buffer) => {
                let offset_start = buffer.offset.start;
                let offset_type = format_ident!("{}", &buffer.offset.ty);
                let offset_subtract = buffer.offset.subtract;
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
                let length_subtract = buffer.length.subtract;

                quote_spanned! { field.span() =>
                    let (remaining, length) = <#length_type>::parse_smb_message(&input[#length_start..])?;
                    current_pos = length.smb_byte_size() + #length_start;
                    let length = length - (#length_subtract as #length_type);
                    #offset_block
                    let offset = offset - (#offset_subtract as #offset_type);
                    println!("{:?}, {:?}", offset, length);
                    let buf_end = offset as usize + length as usize;
                    let #name = input[(offset as usize)..].to_vec();
                    let remaining = &input[buf_end..];
                }
            },
            SMBFieldType::Vector(vector) => {
                let count_start = vector.count.start;
                let count_type = format_ident!("{}", &vector.count.ty);
                let align = vector.align;
                let inner_type = &f.ty;


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
        let field = f.spannable;
        quote_spanned! {field.span() => #name}
    });

    let expanded_stream = match mapping.mapping_type {
        SMBFieldMappingType::NamedStruct => {
            quote! {
                #(#recurse)*
                Ok((remaining, Self {
                    #(#names,)*
                }))
            }
        },
        SMBFieldMappingType::UnnamedStruct => {
            quote! {
                #(#recurse)*
                Ok((remaining, Self (
                    #(#names,)*
                )))
            }
        },
        SMBFieldMappingType::Enum => {
            quote! {
                #(#recurse)*
                let value = Self::try_from(#(#names)*).map_err(|_e| ::smb_core::error::SMBError::ParseError("Invalid primitive value".into()))?;
                Ok((remaining, value))
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

fn smb_byte_size<T: Spanned + PartialEq + Eq + Debug>(mapping: &SMBFieldMapping<T>) -> proc_macro2::TokenStream {
    let err_stream = |span: &T| quote_spanned! {span.span()=>
        ::std::compile_error!("Error generating byte size for field")
    };
    let idents = match mapping.mapping_type {
        SMBFieldMappingType::NamedStruct => mapping.fields.iter().map(|f| {
            let token_stream: proc_macro2::TokenStream = format!("self.{}", f.name.to_string()).parse()
                .unwrap_or_else(|_e| err_stream(f.spannable));
            (f, token_stream)
        }).collect(),
        SMBFieldMappingType::UnnamedStruct => mapping.fields.iter().enumerate().map(|(idx, f)| {
            let token_stream: proc_macro2::TokenStream = format!("self.{}", idx).parse()
                .unwrap_or_else(|_e| err_stream(f.spannable));
            (f, token_stream)
        }).collect(),
        SMBFieldMappingType::Enum => mapping.fields.iter().map(|f| {
            let ty = &f.ty;
            let token_stream = quote! {
                (*self as #ty)
            };
            (f, token_stream)
        }).collect(),
        SMBFieldMappingType::Unit => vec![]
    };

    let size = idents.into_iter().map(|(field, tokens)| {
        quote_spanned! {field.spannable.span() =>
            ::smb_core::SMBFromBytes::smb_byte_size(&#tokens)
        }
    });

    quote! {
        0 #(+ #size)*
    }
}

fn get_value_type(field: &Field) -> Result<SMBFieldType, SMBDeriveError<Field>> {
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
enum SMBDeriveError<T: Spanned + Debug> {
    TypeError(T),
    InvalidType,
}

impl<T: Spanned + Debug> Display for SMBDeriveError<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TypeError(span) => write!(f, "No type annotation for spannable ${:?} (must be buffer or direct)", span),
            Self::InvalidType => write!(f, "Unsupported or invalid type"),
        }
    }
}

impl<T: Spanned + Debug> std::error::Error for SMBDeriveError<T> {}

#[proc_macro_derive(SMBToBytes)]
pub fn smb_to_bytes(_input: TokenStream) -> TokenStream {
    _input
}