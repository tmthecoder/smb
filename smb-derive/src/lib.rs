extern crate proc_macro;

use proc_macro::TokenStream;
use std::cmp::{min, Ordering};
use std::fmt::{Display, Error, Formatter, write};

use darling::{FromDeriveInput, FromField, FromMeta};
use proc_macro2::Ident;
use quote::{quote, quote_each_token, quote_spanned};
use syn::{Data, DeriveInput, Field, Fields, parse_macro_input};
use syn::spanned::Spanned;

#[derive(Debug, FromDeriveInput, FromField, Default, PartialEq, Eq)]
#[darling(attributes(direct))]
struct Direct {
    start: usize,
    length: usize,
}

#[derive(Debug, FromMeta, Default, PartialEq, Eq)]
struct DirectInner {
    start: usize,
    length: usize,
}

#[derive(Debug, FromDeriveInput, FromField, Default, PartialEq, Eq)]
#[darling(attributes(buffer))]
struct Buffer {
    offset: DirectInner,
    length: DirectInner,
}

#[derive(Debug, FromDeriveInput, FromField, Default)]
#[darling(attributes(byte_tag))]
struct ByteTag {
    value: u8,
}

#[derive(FromDeriveInput, FromField, Default, Debug)]
#[darling(attributes(string_tag))]
struct StringTag {
    value: String,
}

#[derive(Debug, PartialEq, Eq)]
struct SMBField<'a> {
    field: &'a Field,
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

    let mapped = get_field_mapping(&input.data);

    if let Err(e) = mapped {
        return match e {
            SMBDeriveError::TypeError(f) => {
                quote_spanned! {
                    f.span() => compile_error!("No type set or incorrectly defined type for field")
                }
            },
            SMBDeriveError::InvalidType => {
                quote_spanned! {
                    input.span() => compile_error!("Invalid or unsupported type")
                }
            }
        }.into()
    }

    let name = input.ident;

    let parser = create_parser(&mapped.unwrap(), name.clone());

    println!("Parser: {:?}", parser.to_string());

    let tokens = quote! {
        impl SMBFromBytes for #name {
            fn parse_smb_message(input: &[u8]) -> Result<Self, smb_reader::util::error::SMBError> {
                #parser
            }
        }
    };

    tokens.into()
}

fn get_field_mapping(data: &Data) -> Result<Vec<SMBField>, SMBDeriveError> {
    let mut mapped_fields: Vec<SMBField> = match *data {
        Data::Struct(ref structure) => {
            match structure.fields {
                Fields::Named(ref fields) => fields.named.iter().map(|field| {
                    let val_type = get_value_type(field)?;
                    Ok(SMBField {
                        field,
                        val_type,
                    })
                }).collect::<Vec<Result<SMBField, SMBDeriveError>>>()
                    .into_iter()
                    .collect::<Result<Vec<SMBField>, SMBDeriveError>>()?,
                _ => return Err(SMBDeriveError::InvalidType)
            }
        },
        _ => return Err(SMBDeriveError::InvalidType)
    };

    mapped_fields.sort();

    Ok(mapped_fields)
}

fn create_parser(fields: &[SMBField], name: Ident) -> proc_macro2::TokenStream {
    let recurse = fields.iter().map(|f| {
        let name = f.field.ident.as_ref().unwrap();
        let field = f.field;
        let ty = &f.field.ty;
        match &f.val_type {
            SMBFieldType::Direct(direct) => {
                let start = direct.start;
                let end = start + direct.length;
                quote_spanned! { field.span() =>
                    let #name = <#ty>::parse_smb_message(&input[#start..#end])?;
                }
            },
            SMBFieldType::Buffer(buffer) => {
                let offset_start = buffer.offset.start;
                let offset_end = offset_start + buffer.offset.length;
                let length_start = buffer.length.start;
                let length_end = length_start + buffer.length.length;

                quote_spanned! {field.span() =>
                    let offset = u32::parse_smb_message(&input[#offset_start..#offset_end])?;
                    let length = u32::parse_smb_message(&input[#length_start..#length_end])?;
                    let #name = input[(offset as usize)..(offset as usize + length as usize)].to_vec();
                }
            }
        }
    });
    let names = fields.iter().map(|f| {
        let name = f.field.ident.as_ref().unwrap();
        let field = f.field;
        quote_spanned! {field.span() => #name}
    });
    quote! {
        #(#recurse)*
        Ok(#name {
            #(#names,)*
        })
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


// pub trait SMBFromBytes {
//
// }

// pub trait SMBToBytes {}

#[proc_macro_derive(SMBToBytes)]
pub fn smb_to_bytes(_input: TokenStream) -> TokenStream {
    _input
}