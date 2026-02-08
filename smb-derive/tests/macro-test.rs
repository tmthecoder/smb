use std::marker::PhantomData;

use smb_core::{SMBByteSize, SMBEnumFromBytes, SMBFromBytes, SMBToBytes};
use smb_derive::{SMBByteSize, SMBEnumFromBytes, SMBFromBytes, SMBToBytes};

// ---------------------------------------------------------------------------
// 1. Simple struct with smb_direct fields at fixed offsets
// ---------------------------------------------------------------------------

/// Mimics a minimal SMB2-style struct: two fixed-size fields at known offsets.
#[derive(Debug, PartialEq, Eq, SMBFromBytes, SMBToBytes, SMBByteSize)]
struct TwoFields {
    #[smb_direct(start(fixed = 0))]
    field_a: u16,
    #[smb_direct(start(fixed = 2))]
    field_b: u32,
}

#[test]
fn two_fields_byte_size() {
    let val = TwoFields { field_a: 1, field_b: 2 };
    assert_eq!(val.smb_byte_size(), 6); // 2 + 4
}

#[test]
fn two_fields_roundtrip() {
    let original = TwoFields { field_a: 0x1234, field_b: 0xDEADBEEF };
    let bytes = original.smb_to_bytes();
    assert_eq!(bytes.len(), 6);
    // Little-endian checks
    assert_eq!(bytes[0], 0x34);
    assert_eq!(bytes[1], 0x12);
    assert_eq!(bytes[2], 0xEF);
    assert_eq!(bytes[3], 0xBE);
    assert_eq!(bytes[4], 0xAD);
    assert_eq!(bytes[5], 0xDE);

    let (remaining, parsed) = TwoFields::smb_from_bytes(&bytes).unwrap();
    assert_eq!(parsed, original);
    assert!(remaining.is_empty() || remaining.len() == 0);
}

#[test]
fn two_fields_from_bytes_with_trailing() {
    let bytes: Vec<u8> = vec![0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0xFF, 0xFF];
    let (remaining, parsed) = TwoFields::smb_from_bytes(&bytes).unwrap();
    assert_eq!(parsed, TwoFields { field_a: 1, field_b: 2 });
    assert_eq!(remaining, &[0xFF, 0xFF]);
}

#[test]
fn two_fields_from_bytes_too_short() {
    let bytes: Vec<u8> = vec![0x01, 0x00, 0x02];
    assert!(TwoFields::smb_from_bytes(&bytes).is_err());
}

// ---------------------------------------------------------------------------
// 2. Struct with smb_skip (reserved/padding bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq, SMBFromBytes, SMBToBytes, SMBByteSize)]
struct WithSkip {
    #[smb_direct(start(fixed = 0))]
    value: u16,
    #[smb_skip(start = 2, length = 2)]
    _reserved: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 4))]
    after_skip: u32,
}

#[test]
fn skip_roundtrip() {
    let original = WithSkip {
        value: 0x0A0B,
        _reserved: PhantomData,
        after_skip: 0x01020304,
    };
    let bytes = original.smb_to_bytes();
    assert_eq!(bytes.len(), 8);
    // Bytes 2-3 should be zero (skip region)
    assert_eq!(bytes[2], 0x00);
    assert_eq!(bytes[3], 0x00);

    let (_remaining, parsed) = WithSkip::smb_from_bytes(&bytes).unwrap();
    assert_eq!(parsed.value, original.value);
    assert_eq!(parsed.after_skip, original.after_skip);
}

#[test]
fn skip_with_value_roundtrip() {
    #[derive(Debug, PartialEq, Eq, SMBFromBytes, SMBToBytes, SMBByteSize)]
    struct SkipWithValue {
        #[smb_direct(start(fixed = 0))]
        value: u16,
        #[smb_skip(start = 2, length = 2, value = "[0xFF, 0xFE]")]
        _reserved: PhantomData<Vec<u8>>,
        #[smb_direct(start(fixed = 4))]
        after_skip: u16,
    }

    let original = SkipWithValue {
        value: 42,
        _reserved: PhantomData,
        after_skip: 99,
    };
    let bytes = original.smb_to_bytes();
    assert_eq!(bytes[2], 0xFF);
    assert_eq!(bytes[3], 0xFE);
}

// ---------------------------------------------------------------------------
// 3. Struct with smb_byte_tag (StructureSize sentinel)
//    NOTE: byte_tag structs require 2+ fields due to the single-field
//    code path in get_struct_field_mapping merging parent attrs into the
//    field's val_types, which breaks smb_to_bytes variable scoping.
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq, SMBFromBytes, SMBToBytes, SMBByteSize)]
#[smb_byte_tag(value = 9)]
struct WithByteTag {
    #[smb_direct(start(fixed = 2))]
    flags: u16,
    #[smb_direct(start(fixed = 4))]
    extra: u16,
}

#[test]
fn byte_tag_to_bytes() {
    let val = WithByteTag { flags: 0x0001, extra: 0 };
    let bytes = val.smb_to_bytes();
    // First byte should be the tag value (9)
    assert_eq!(bytes[0], 9);
    // flags at offset 2
    assert_eq!(bytes[2], 0x01);
    assert_eq!(bytes[3], 0x00);
}

#[test]
fn byte_tag_from_bytes() {
    let bytes: Vec<u8> = vec![9, 0x00, 0x03, 0x00, 0x00, 0x00];
    let (_remaining, parsed) = WithByteTag::smb_from_bytes(&bytes).unwrap();
    assert_eq!(parsed.flags, 3);
}

#[test]
fn byte_tag_wrong_value_scans_forward() {
    // ByteTag scans forward until it finds the matching byte.
    // smb_direct(start(fixed = 2)) reads from ABSOLUTE offset 2 in the input,
    // not relative to the tag position.
    let bytes: Vec<u8> = vec![0x00, 9, 0x05, 0x00, 0x00, 0x00, 0x00];
    let (_remaining, parsed) = WithByteTag::smb_from_bytes(&bytes).unwrap();
    // Tag found at index 1, but flags still read from absolute offset 2
    assert_eq!(parsed.flags, 5);
}

// ---------------------------------------------------------------------------
// 4. Struct with smb_buffer (offset/length variable buffer)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq, SMBFromBytes, SMBToBytes, SMBByteSize)]
struct WithBuffer {
    #[smb_direct(start(fixed = 0))]
    header_val: u16,
    #[smb_buffer(
        offset(inner(start = 2, num_type = "u16")),
        length(inner(start = 4, num_type = "u16"))
    )]
    data: Vec<u8>,
}

#[test]
fn buffer_from_bytes() {
    // header_val at 0..2, offset at 2..4 = 6, length at 4..6 = 3, data at 6..9
    let bytes: Vec<u8> = vec![
        0x42, 0x00, // header_val = 0x0042
        0x06, 0x00, // offset = 6
        0x03, 0x00, // length = 3
        0xAA, 0xBB, 0xCC, // data
    ];
    let (_remaining, parsed) = WithBuffer::smb_from_bytes(&bytes).unwrap();
    assert_eq!(parsed.header_val, 0x0042);
    assert_eq!(parsed.data, vec![0xAA, 0xBB, 0xCC]);
}

// ---------------------------------------------------------------------------
// 5. Numeric enum with #[repr(u16)]
// ---------------------------------------------------------------------------

#[derive(
    Debug, PartialEq, Eq, Clone, Copy,
    SMBFromBytes, SMBToBytes, SMBByteSize,
    num_enum::TryFromPrimitive,
)]
#[repr(u16)]
enum SimpleCommand {
    Negotiate = 0x0000,
    SessionSetup = 0x0001,
    Logoff = 0x0002,
}

#[test]
fn num_enum_byte_size() {
    assert_eq!(SimpleCommand::Negotiate.smb_byte_size(), 2);
    assert_eq!(SimpleCommand::SessionSetup.smb_byte_size(), 2);
}

#[test]
fn num_enum_roundtrip() {
    let cmd = SimpleCommand::SessionSetup;
    let bytes = cmd.smb_to_bytes();
    assert_eq!(bytes, vec![0x01, 0x00]);

    let (_remaining, parsed) = SimpleCommand::smb_from_bytes(&bytes).unwrap();
    assert_eq!(parsed, SimpleCommand::SessionSetup);
}

#[test]
fn num_enum_invalid_value() {
    let bytes: Vec<u8> = vec![0xFF, 0xFF];
    assert!(SimpleCommand::smb_from_bytes(&bytes).is_err());
}

// ---------------------------------------------------------------------------
// 6. Discriminated enum with SMBEnumFromBytes
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes)]
struct PayloadA {
    #[smb_direct(start(fixed = 0))]
    val: u32,
}

// Manual impls for PayloadA since it's used inside the discriminated enum
impl SMBFromBytes for PayloadA {
    fn smb_from_bytes(input: &[u8]) -> smb_core::SMBParseResult<&[u8], Self> {
        let (remaining, val) = u32::smb_from_bytes(input)?;
        Ok((remaining, PayloadA { val }))
    }
}

#[derive(Debug, PartialEq, Eq, SMBEnumFromBytes, SMBByteSize, SMBToBytes)]
enum DiscEnum {
    #[smb_discriminator(value = 1)]
    #[smb_direct(start(fixed = 0))]
    VariantA(u32),
    #[smb_discriminator(value = 2)]
    #[smb_direct(start(fixed = 0))]
    VariantB(u16),
}

#[test]
fn disc_enum_from_bytes_variant_a() {
    let bytes: Vec<u8> = vec![0x78, 0x56, 0x34, 0x12];
    let (_remaining, parsed) = DiscEnum::smb_enum_from_bytes(&bytes, 1).unwrap();
    assert_eq!(parsed, DiscEnum::VariantA(0x12345678));
}

#[test]
fn disc_enum_from_bytes_variant_b() {
    let bytes: Vec<u8> = vec![0xCD, 0xAB];
    let (_remaining, parsed) = DiscEnum::smb_enum_from_bytes(&bytes, 2).unwrap();
    assert_eq!(parsed, DiscEnum::VariantB(0xABCD));
}

#[test]
fn disc_enum_invalid_discriminator() {
    let bytes: Vec<u8> = vec![0x00, 0x00, 0x00, 0x00];
    assert!(DiscEnum::smb_enum_from_bytes(&bytes, 99).is_err());
}

#[test]
fn disc_enum_byte_size() {
    assert_eq!(DiscEnum::VariantA(0).smb_byte_size(), 4);
    assert_eq!(DiscEnum::VariantB(0).smb_byte_size(), 2);
}

#[test]
fn disc_enum_to_bytes() {
    let a = DiscEnum::VariantA(0x01020304);
    let bytes = a.smb_to_bytes();
    assert_eq!(bytes, vec![0x04, 0x03, 0x02, 0x01]);

    let b = DiscEnum::VariantB(0x0506);
    let bytes = b.smb_to_bytes();
    assert_eq!(bytes, vec![0x06, 0x05]);
}

// ---------------------------------------------------------------------------
// 7. Discriminated enum with multiple discriminator values
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq, SMBEnumFromBytes, SMBByteSize, SMBToBytes)]
enum MultiDisc {
    #[smb_discriminator(value = 1, value = 2, value = 3)]
    #[smb_direct(start(fixed = 0))]
    Common(u8),
    #[smb_discriminator(value = 10)]
    #[smb_direct(start(fixed = 0))]
    Special(u8),
}

#[test]
fn multi_disc_all_values_match() {
    let bytes: Vec<u8> = vec![42];
    for disc in [1u64, 2, 3] {
        let (_rem, parsed) = MultiDisc::smb_enum_from_bytes(&bytes, disc).unwrap();
        assert_eq!(parsed, MultiDisc::Common(42));
    }
    let (_rem, parsed) = MultiDisc::smb_enum_from_bytes(&bytes, 10).unwrap();
    assert_eq!(parsed, MultiDisc::Special(42));
}

// ---------------------------------------------------------------------------
// 8. Struct with multiple fields at various offsets (gap between fields)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq, SMBFromBytes, SMBToBytes, SMBByteSize)]
struct Gapped {
    #[smb_direct(start(fixed = 0))]
    first: u8,
    #[smb_direct(start(fixed = 4))]
    second: u32,
}

#[test]
fn gapped_roundtrip() {
    let original = Gapped { first: 0xAA, second: 0x11223344 };
    let bytes = original.smb_to_bytes();
    // Byte 0 = 0xAA, bytes 1-3 = 0 (gap), bytes 4-7 = LE 0x11223344
    assert_eq!(bytes[0], 0xAA);
    assert_eq!(bytes[1], 0x00);
    assert_eq!(bytes[2], 0x00);
    assert_eq!(bytes[3], 0x00);
    assert_eq!(bytes[4], 0x44);
    assert_eq!(bytes[5], 0x33);
    assert_eq!(bytes[6], 0x22);
    assert_eq!(bytes[7], 0x11);

    let (_remaining, parsed) = Gapped::smb_from_bytes(&bytes).unwrap();
    assert_eq!(parsed, original);
}

// ---------------------------------------------------------------------------
// 9. Single-field named struct (newtype-like)
//    NOTE: Tuple structs (unnamed fields) have a codegen bug in SMBToBytes
//    where the generated code references `self.val_0` instead of `self.0`.
//    Use a named field as a workaround.
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq, SMBFromBytes, SMBToBytes, SMBByteSize)]
struct Wrapper {
    #[smb_direct(start(fixed = 0))]
    inner: u32,
}

#[test]
fn wrapper_roundtrip() {
    let original = Wrapper { inner: 0xCAFEBABE };
    let bytes = original.smb_to_bytes();
    assert_eq!(bytes, vec![0xBE, 0xBA, 0xFE, 0xCA]);

    let (_remaining, parsed) = Wrapper::smb_from_bytes(&bytes).unwrap();
    assert_eq!(parsed, original);
}

// ---------------------------------------------------------------------------
// 10. Numeric enum with u8 repr
// ---------------------------------------------------------------------------

#[derive(
    Debug, PartialEq, Eq, Clone, Copy,
    SMBFromBytes, SMBToBytes, SMBByteSize,
    num_enum::TryFromPrimitive,
)]
#[repr(u8)]
enum SmallEnum {
    A = 0,
    B = 1,
    C = 255,
}

#[test]
fn small_enum_roundtrip() {
    for (variant, expected_byte) in [
        (SmallEnum::A, 0u8),
        (SmallEnum::B, 1),
        (SmallEnum::C, 255),
    ] {
        let bytes = variant.smb_to_bytes();
        assert_eq!(bytes, vec![expected_byte]);
        let (_rem, parsed) = SmallEnum::smb_from_bytes(&bytes).unwrap();
        assert_eq!(parsed, variant);
    }
}

// ---------------------------------------------------------------------------
// 11. Struct with smb_byte_tag + smb_string_tag (like SMBSyncHeader)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq, SMBFromBytes, SMBToBytes, SMBByteSize)]
#[smb_byte_tag(value = 0xFE, order = 0)]
#[smb_string_tag(value = "SMB", order = 1)]
struct HeaderLike {
    #[smb_direct(start(fixed = 4))]
    value: u16,
    #[smb_direct(start(fixed = 6))]
    extra: u16,
}

#[test]
fn header_like_to_bytes() {
    let val = HeaderLike { value: 0x0040, extra: 0 };
    let bytes = val.smb_to_bytes();
    assert_eq!(bytes[0], 0xFE);
    assert_eq!(&bytes[1..4], b"SMB");
    assert_eq!(bytes[4], 0x40);
    assert_eq!(bytes[5], 0x00);
}

#[test]
fn header_like_from_bytes() {
    let bytes: Vec<u8> = vec![0xFE, b'S', b'M', b'B', 0x40, 0x00, 0x00, 0x00];
    let (_remaining, parsed) = HeaderLike::smb_from_bytes(&bytes).unwrap();
    assert_eq!(parsed.value, 0x0040);
}

// ---------------------------------------------------------------------------
// 12. Struct with inner offset (subtract pattern)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq, SMBFromBytes, SMBToBytes, SMBByteSize)]
#[smb_byte_tag(value = 9)]
struct WithInnerOffset {
    #[smb_direct(start(fixed = 2))]
    flags: u16,
    #[smb_buffer(
        offset(inner(start = 4, num_type = "u16", subtract = 64, min_val = 72)),
        length(inner(start = 6, num_type = "u16"))
    )]
    buffer: Vec<u8>,
}

#[test]
fn inner_offset_from_bytes() {
    // Build a buffer that looks like:
    // [0] = 9 (tag)
    // [1] = 0 (padding)
    // [2..4] = flags = 0x0001
    // [4..6] = offset = 72 (raw wire value, subtract 64 = 8 = actual offset in body)
    // [6..8] = length = 3
    // [8..11] = buffer data
    let mut bytes = vec![0u8; 11];
    bytes[0] = 9;
    // flags
    bytes[2] = 0x01;
    bytes[3] = 0x00;
    // offset = 72
    bytes[4] = 72;
    bytes[5] = 0;
    // length = 3
    bytes[6] = 3;
    bytes[7] = 0;
    // buffer data
    bytes[8] = 0xAA;
    bytes[9] = 0xBB;
    bytes[10] = 0xCC;

    let (_remaining, parsed) = WithInnerOffset::smb_from_bytes(&bytes).unwrap();
    assert_eq!(parsed.flags, 1);
    assert_eq!(parsed.buffer, vec![0xAA, 0xBB, 0xCC]);
}