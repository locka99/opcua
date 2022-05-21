use std::convert::TryFrom;
use std::str::FromStr;

use crate::types::{
    numeric_range::NumericRange,
    status_code::StatusCode,
    variant::{Variant, VariantTypeId},
    ByteString, DataTypeId, DataValue, DateTime, DiagnosticInfo, ExpandedNodeId, Guid,
    LocalizedText, NodeId, QualifiedName, UAString,
};

#[test]
fn is_numeric() {
    assert!(Variant::from(10i8).is_numeric());
    assert!(Variant::from(10u8).is_numeric());
    assert!(Variant::from(10i16).is_numeric());
    assert!(Variant::from(10u16).is_numeric());
    assert!(Variant::from(10i32).is_numeric());
    assert!(Variant::from(10u32).is_numeric());
    assert!(Variant::from(10i64).is_numeric());
    assert!(Variant::from(10u64).is_numeric());
    assert!(Variant::from(10f32).is_numeric());
    assert!(Variant::from(10f64).is_numeric());

    assert_eq!(Variant::from("foo").is_numeric(), false);
    assert_eq!(Variant::from(true).is_numeric(), false);
}

#[test]
fn size() {
    // Test that the variant is boxing enough data to keep the stack size down to some manageable
    // amount.
    use std::mem;
    let vsize = mem::size_of::<Variant>();
    println!("Variant size = {}", vsize);
    assert!(vsize <= 32);
}

#[test]
fn variant_type_id() {
    use crate::types::{
        status_codes::StatusCode, ByteString, DateTime, ExpandedNodeId, ExtensionObject, Guid,
        LocalizedText, NodeId, QualifiedName, UAString, XmlElement,
    };

    let types = [
        (Variant::Empty, VariantTypeId::Empty),
        (Variant::from(true), VariantTypeId::Boolean),
        (Variant::from(0i8), VariantTypeId::SByte),
        (Variant::from(0u8), VariantTypeId::Byte),
        (Variant::from(0i16), VariantTypeId::Int16),
        (Variant::from(0u16), VariantTypeId::UInt16),
        (Variant::from(0i32), VariantTypeId::Int32),
        (Variant::from(0u32), VariantTypeId::UInt32),
        (Variant::from(0i64), VariantTypeId::Int64),
        (Variant::from(0u64), VariantTypeId::UInt64),
        (Variant::from(0f32), VariantTypeId::Float),
        (Variant::from(0f64), VariantTypeId::Double),
        (Variant::from(UAString::null()), VariantTypeId::String),
        (Variant::from(ByteString::null()), VariantTypeId::ByteString),
        (
            Variant::XmlElement(XmlElement::null()),
            VariantTypeId::XmlElement,
        ),
        (Variant::from(StatusCode::Good), VariantTypeId::StatusCode),
        (Variant::from(DateTime::now()), VariantTypeId::DateTime),
        (Variant::from(Guid::new()), VariantTypeId::Guid),
        (Variant::from(NodeId::null()), VariantTypeId::NodeId),
        (
            Variant::from(ExpandedNodeId::null()),
            VariantTypeId::ExpandedNodeId,
        ),
        (
            Variant::from(QualifiedName::null()),
            VariantTypeId::QualifiedName,
        ),
        (
            Variant::from(LocalizedText::null()),
            VariantTypeId::LocalizedText,
        ),
        (
            Variant::from(ExtensionObject::null()),
            VariantTypeId::ExtensionObject,
        ),
        (Variant::from(DataValue::null()), VariantTypeId::DataValue),
        (
            Variant::Variant(Box::new(Variant::from(32u8))),
            VariantTypeId::Variant,
        ),
        (
            Variant::from(DiagnosticInfo::null()),
            VariantTypeId::Diagnostic,
        ),
        (Variant::from(vec![1]), VariantTypeId::Array),
    ];
    for t in &types {
        assert_eq!(t.0.type_id(), t.1);
    }
}

#[test]
fn variant_u32_array() {
    let vars = [1u32, 2u32, 3u32];
    let v = Variant::from(&vars[..]);
    assert!(v.is_array());
    assert!(v.is_array_of_type(VariantTypeId::UInt32));
    assert!(v.is_valid());

    match v {
        Variant::Array(array) => {
            let values = array.values;
            assert_eq!(values.len(), 3);
            let mut i = 1u32;
            for v in values {
                assert!(v.is_numeric());
                match v {
                    Variant::UInt32(v) => {
                        assert_eq!(v, i);
                    }
                    _ => panic!("Not the expected type"),
                }
                i += 1;
            }
        }
        _ => panic!("Not an array"),
    }
}

#[test]
fn variant_try_into_u32_array() {
    let vars = [1u32, 2u32, 3u32];
    let v = Variant::from(&vars[..]);
    assert!(v.is_array());
    assert!(v.is_array_of_type(VariantTypeId::UInt32));
    assert!(v.is_valid());

    let result = <Vec<u32>>::try_from(&v).unwrap();
    assert_eq!(result.len(), 3);
}

#[test]
fn variant_i32_array() {
    let vars = [1, 2, 3];
    let v = Variant::from(&vars[..]);
    assert!(v.is_array());
    assert!(v.is_array_of_type(VariantTypeId::Int32));
    assert!(v.is_valid());

    match v {
        Variant::Array(array) => {
            let values = array.values;
            assert_eq!(values.len(), 3);
            let mut i = 1;
            for v in values {
                assert!(v.is_numeric());
                match v {
                    Variant::Int32(v) => {
                        assert_eq!(v, i);
                    }
                    _ => panic!("Not the expected type"),
                }
                i += 1;
            }
        }
        _ => panic!("Not an array"),
    }
}

#[test]
fn variant_multi_dimensional_array() {
    let v = Variant::from((VariantTypeId::Int32, vec![Variant::from(10)], vec![1u32]));
    assert!(v.is_array());
    assert!(v.is_array_of_type(VariantTypeId::Int32));
    assert!(v.is_valid());

    let v = Variant::from((
        VariantTypeId::Int32,
        vec![Variant::from(10), Variant::from(10)],
        vec![2u32],
    ));
    assert!(v.is_array());
    assert!(v.is_array_of_type(VariantTypeId::Int32));
    assert!(v.is_valid());

    let v = Variant::from((
        VariantTypeId::Int32,
        vec![Variant::from(10), Variant::from(10)],
        vec![1u32, 2u32],
    ));
    assert!(v.is_array());
    assert!(v.is_array_of_type(VariantTypeId::Int32));
    assert!(v.is_valid());

    let v = Variant::from((
        VariantTypeId::Int32,
        vec![Variant::from(10), Variant::from(10)],
        vec![1u32, 2u32, 3u32],
    ));
    assert!(v.is_array());
    assert!(v.is_array_of_type(VariantTypeId::Int32));
    assert!(!v.is_valid());
}

#[test]
fn index_of_array() {
    let vars: Vec<Variant> = [1, 2, 3].iter().map(|v| Variant::from(*v)).collect();
    let v = Variant::from((VariantTypeId::Int32, vars));
    assert!(v.is_array());

    let r = v.range_of(NumericRange::None).unwrap();
    assert_eq!(r, v);

    let r = v.range_of(NumericRange::Index(1)).unwrap();
    match r {
        Variant::Array(array) => {
            assert_eq!(array.values.len(), 1);
            assert_eq!(array.values[0], Variant::Int32(2));
        }
        _ => panic!(),
    }

    let r = v.range_of(NumericRange::Range(1, 2)).unwrap();
    match r {
        Variant::Array(array) => {
            assert_eq!(array.values.len(), 2);
            assert_eq!(array.values[0], Variant::Int32(2));
            assert_eq!(array.values[1], Variant::Int32(3));
        }
        _ => panic!(),
    }

    let r = v.range_of(NumericRange::Range(1, 200)).unwrap();
    match r {
        Variant::Array(array) => {
            assert_eq!(array.values.len(), 2);
        }
        _ => panic!(),
    }

    let r = v.range_of(NumericRange::Range(3, 200)).unwrap_err();
    assert_eq!(r, StatusCode::BadIndexRangeNoData);
}

#[test]
fn index_of_string() {
    let v: Variant = "Hello World".into();

    let r = v.range_of(NumericRange::None).unwrap();
    assert_eq!(r, v);

    // Letter W
    let r = v.range_of(NumericRange::Index(6)).unwrap();
    assert_eq!(r, Variant::from("W"));

    let r = v.range_of(NumericRange::Range(6, 100)).unwrap();
    assert_eq!(r, Variant::from("World"));

    let r = v.range_of(NumericRange::Range(11, 200)).unwrap_err();
    assert_eq!(r, StatusCode::BadIndexRangeNoData);
}

fn ensure_conversion_fails(v: &Variant, convert_to: &[VariantTypeId]) {
    convert_to
        .iter()
        .for_each(|vt| assert_eq!(v.convert(*vt), Variant::Empty));
}

#[test]
fn variant_convert_bool() {
    let v: Variant = true.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(v.convert(VariantTypeId::SByte), Variant::SByte(1));
    assert_eq!(v.convert(VariantTypeId::Byte), Variant::Byte(1));
    assert_eq!(v.convert(VariantTypeId::Double), Variant::Double(1.0));
    assert_eq!(v.convert(VariantTypeId::Float), Variant::Float(1.0));
    assert_eq!(v.convert(VariantTypeId::Int16), Variant::Int16(1));
    assert_eq!(v.convert(VariantTypeId::UInt16), Variant::UInt16(1));
    assert_eq!(v.convert(VariantTypeId::Int32), Variant::Int32(1));
    assert_eq!(v.convert(VariantTypeId::UInt32), Variant::UInt32(1));
    assert_eq!(v.convert(VariantTypeId::Int64), Variant::Int64(1));
    assert_eq!(v.convert(VariantTypeId::UInt64), Variant::UInt64(1));
    // Impermissible
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::ByteString,
            VariantTypeId::String,
            VariantTypeId::DateTime,
            VariantTypeId::ExpandedNodeId,
            VariantTypeId::Guid,
            VariantTypeId::NodeId,
            VariantTypeId::StatusCode,
            VariantTypeId::LocalizedText,
            VariantTypeId::QualifiedName,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_bool() {
    // String
    assert_eq!(
        Variant::from(false).cast(VariantTypeId::String),
        Variant::from("false")
    );
    assert_eq!(
        Variant::from(true).cast(VariantTypeId::String),
        Variant::from("true")
    );
}

#[test]
fn variant_convert_byte() {
    let v: Variant = 5u8.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(v.convert(VariantTypeId::Double), Variant::Double(5.0));
    assert_eq!(v.convert(VariantTypeId::Float), Variant::Float(5.0));
    assert_eq!(v.convert(VariantTypeId::Int16), Variant::Int16(5));
    assert_eq!(v.convert(VariantTypeId::Int32), Variant::Int32(5));
    assert_eq!(v.convert(VariantTypeId::Int64), Variant::Int64(5));
    assert_eq!(v.convert(VariantTypeId::SByte), Variant::SByte(5));
    assert_eq!(v.convert(VariantTypeId::UInt16), Variant::UInt16(5));
    assert_eq!(v.convert(VariantTypeId::UInt32), Variant::UInt32(5));
    assert_eq!(v.convert(VariantTypeId::UInt64), Variant::UInt64(5));
    // Impermissible
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::Boolean,
            VariantTypeId::String,
            VariantTypeId::ByteString,
            VariantTypeId::DateTime,
            VariantTypeId::ExpandedNodeId,
            VariantTypeId::Guid,
            VariantTypeId::NodeId,
            VariantTypeId::StatusCode,
            VariantTypeId::LocalizedText,
            VariantTypeId::QualifiedName,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_byte() {
    let v: Variant = 5u8.into();
    // Boolean
    assert_eq!(
        Variant::from(11u8).cast(VariantTypeId::Boolean),
        Variant::Empty
    );
    assert_eq!(
        Variant::from(1u8).cast(VariantTypeId::Boolean),
        Variant::from(true)
    );
    // String
    assert_eq!(v.cast(VariantTypeId::String), Variant::from("5"));
}

#[test]
fn variant_convert_double() {
    let v: Variant = 12.5f64.into();
    assert_eq!(v.convert(v.type_id()), v);
    // Impermissible
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::Boolean,
            VariantTypeId::Byte,
            VariantTypeId::ByteString,
            VariantTypeId::DateTime,
            VariantTypeId::ExpandedNodeId,
            VariantTypeId::Float,
            VariantTypeId::Guid,
            VariantTypeId::Int16,
            VariantTypeId::Int32,
            VariantTypeId::Int64,
            VariantTypeId::NodeId,
            VariantTypeId::SByte,
            VariantTypeId::StatusCode,
            VariantTypeId::String,
            VariantTypeId::LocalizedText,
            VariantTypeId::QualifiedName,
            VariantTypeId::UInt16,
            VariantTypeId::UInt32,
            VariantTypeId::UInt64,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_double() {
    let v: Variant = 12.5f64.into();
    // Cast Boolean
    assert_eq!(
        Variant::from(11f64).cast(VariantTypeId::Boolean),
        Variant::Empty
    );
    assert_eq!(
        Variant::from(1f64).cast(VariantTypeId::Boolean),
        Variant::from(true)
    );
    //  Cast Byte, Float, Int16, Int32, Int64, SByte, UInt16, UInt32, UInt64
    assert_eq!(v.cast(VariantTypeId::Byte), Variant::from(13u8));
    assert_eq!(v.cast(VariantTypeId::Float), Variant::from(12.5f32));
    assert_eq!(v.cast(VariantTypeId::Int16), Variant::from(13i16));
    assert_eq!(v.cast(VariantTypeId::Int32), Variant::from(13i32));
    assert_eq!(v.cast(VariantTypeId::Int64), Variant::from(13i64));
    assert_eq!(v.cast(VariantTypeId::SByte), Variant::from(13i8));
    assert_eq!(v.cast(VariantTypeId::UInt16), Variant::from(13u16));
    assert_eq!(v.cast(VariantTypeId::UInt32), Variant::from(13u32));
    assert_eq!(v.cast(VariantTypeId::UInt64), Variant::from(13u64));
    assert_eq!(v.cast(VariantTypeId::String), Variant::from("12.5"));
}

#[test]
fn variant_convert_float() {
    let v: Variant = 12.5f32.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(v.convert(VariantTypeId::Double), Variant::Double(12.5));
    // Impermissible
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::Boolean,
            VariantTypeId::Byte,
            VariantTypeId::ByteString,
            VariantTypeId::DateTime,
            VariantTypeId::ExpandedNodeId,
            VariantTypeId::Guid,
            VariantTypeId::Int16,
            VariantTypeId::Int32,
            VariantTypeId::Int64,
            VariantTypeId::NodeId,
            VariantTypeId::SByte,
            VariantTypeId::StatusCode,
            VariantTypeId::String,
            VariantTypeId::LocalizedText,
            VariantTypeId::QualifiedName,
            VariantTypeId::UInt16,
            VariantTypeId::UInt32,
            VariantTypeId::UInt64,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_float() {
    let v: Variant = 12.5f32.into();
    // Boolean
    assert_eq!(
        Variant::from(11f32).cast(VariantTypeId::Boolean),
        Variant::Empty
    );
    assert_eq!(
        Variant::from(1f32).cast(VariantTypeId::Boolean),
        Variant::from(true)
    );
    // Cast
    assert_eq!(v.cast(VariantTypeId::Byte), Variant::from(13u8));
    assert_eq!(v.cast(VariantTypeId::Int16), Variant::from(13i16));
    assert_eq!(v.cast(VariantTypeId::Int32), Variant::from(13i32));
    assert_eq!(v.cast(VariantTypeId::Int64), Variant::from(13i64));
    assert_eq!(v.cast(VariantTypeId::SByte), Variant::from(13i8));
    assert_eq!(v.cast(VariantTypeId::UInt16), Variant::from(13u16));
    assert_eq!(v.cast(VariantTypeId::UInt32), Variant::from(13u32));
    assert_eq!(v.cast(VariantTypeId::UInt64), Variant::from(13u64));
    assert_eq!(v.cast(VariantTypeId::String), Variant::from("12.5"));
}

#[test]
fn variant_convert_int16() {
    let v: Variant = 8i16.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(v.convert(VariantTypeId::Double), Variant::Double(8.0));
    assert_eq!(v.convert(VariantTypeId::Float), Variant::Float(8.0));
    assert_eq!(v.convert(VariantTypeId::Int32), Variant::Int32(8));
    assert_eq!(v.convert(VariantTypeId::Int64), Variant::Int64(8));
    assert_eq!(v.convert(VariantTypeId::UInt32), Variant::UInt32(8));
    assert_eq!(v.convert(VariantTypeId::UInt64), Variant::UInt64(8));
    // Impermissible
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::Boolean,
            VariantTypeId::Byte,
            VariantTypeId::ByteString,
            VariantTypeId::DateTime,
            VariantTypeId::ExpandedNodeId,
            VariantTypeId::Guid,
            VariantTypeId::SByte,
            VariantTypeId::NodeId,
            VariantTypeId::StatusCode,
            VariantTypeId::String,
            VariantTypeId::LocalizedText,
            VariantTypeId::QualifiedName,
            VariantTypeId::UInt16,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_int16() {
    let v: Variant = 8i16.into();
    // Cast Boolean, Byte, SByte, String, UInt16
    assert_eq!(v.cast(VariantTypeId::Boolean), Variant::Empty);
    assert_eq!(
        Variant::from(1i16).cast(VariantTypeId::Boolean),
        Variant::from(true)
    );
    assert_eq!(v.cast(VariantTypeId::Byte), Variant::from(8u8));
    assert_eq!(
        Variant::from(-120i16).cast(VariantTypeId::Byte),
        Variant::Empty
    );
    assert_eq!(v.cast(VariantTypeId::SByte), Variant::from(8i8));
    assert_eq!(
        Variant::from(-137i16).cast(VariantTypeId::SByte),
        Variant::Empty
    );
    assert_eq!(v.cast(VariantTypeId::String), Variant::from("8"));
    assert_eq!(v.cast(VariantTypeId::UInt16), Variant::from(8u16));
}

#[test]
fn variant_convert_int32() {
    let v: Variant = 9i32.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(v.convert(VariantTypeId::Double), Variant::Double(9.0));
    assert_eq!(v.convert(VariantTypeId::Float), Variant::Float(9.0));
    assert_eq!(v.convert(VariantTypeId::Int64), Variant::Int64(9));
    assert_eq!(v.convert(VariantTypeId::UInt64), Variant::UInt64(9));
    // Impermissible
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::Boolean,
            VariantTypeId::Byte,
            VariantTypeId::ByteString,
            VariantTypeId::DateTime,
            VariantTypeId::ExpandedNodeId,
            VariantTypeId::Guid,
            VariantTypeId::Int16,
            VariantTypeId::NodeId,
            VariantTypeId::SByte,
            VariantTypeId::StatusCode,
            VariantTypeId::String,
            VariantTypeId::LocalizedText,
            VariantTypeId::QualifiedName,
            VariantTypeId::UInt16,
            VariantTypeId::UInt32,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_int32() {
    let v: Variant = 9i32.into();
    // Boolean
    assert_eq!(v.cast(VariantTypeId::Boolean), Variant::Empty);
    assert_eq!(
        Variant::from(1i32).cast(VariantTypeId::Boolean),
        Variant::from(true)
    );
    // Byte
    assert_eq!(v.cast(VariantTypeId::Byte), Variant::from(9u8));
    assert_eq!(
        Variant::from(-120i32).cast(VariantTypeId::Byte),
        Variant::Empty
    );
    // Int16
    assert_eq!(v.cast(VariantTypeId::Int16), Variant::from(9i16));
    // SByte
    assert_eq!(v.cast(VariantTypeId::SByte), Variant::from(9i8));
    assert_eq!(
        Variant::from(-137i32).cast(VariantTypeId::SByte),
        Variant::Empty
    );
    // StatusCode
    let status_code = StatusCode::BadResourceUnavailable
        | StatusCode::HISTORICAL_RAW
        | StatusCode::SEMANTICS_CHANGED;
    assert_eq!(
        Variant::from(status_code.bits() as i32).cast(VariantTypeId::StatusCode),
        Variant::from(status_code)
    );
    // String
    assert_eq!(v.cast(VariantTypeId::String), Variant::from("9"));
    // UInt16
    assert_eq!(v.cast(VariantTypeId::UInt16), Variant::from(9u16));
    assert_eq!(
        Variant::from(-120i32).cast(VariantTypeId::UInt16),
        Variant::Empty
    );
    // UInt32
    assert_eq!(v.cast(VariantTypeId::UInt32), Variant::from(9u32));
    assert_eq!(
        Variant::from(-120i32).cast(VariantTypeId::UInt32),
        Variant::Empty
    );
}

#[test]
fn variant_convert_int64() {
    let v: Variant = 10i64.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(v.convert(VariantTypeId::Double), Variant::Double(10.0));
    assert_eq!(v.convert(VariantTypeId::Float), Variant::Float(10.0));
    // Impermissible
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::Boolean,
            VariantTypeId::Byte,
            VariantTypeId::ByteString,
            VariantTypeId::DateTime,
            VariantTypeId::ExpandedNodeId,
            VariantTypeId::Guid,
            VariantTypeId::Int16,
            VariantTypeId::Int32,
            VariantTypeId::NodeId,
            VariantTypeId::SByte,
            VariantTypeId::StatusCode,
            VariantTypeId::String,
            VariantTypeId::LocalizedText,
            VariantTypeId::QualifiedName,
            VariantTypeId::UInt16,
            VariantTypeId::UInt32,
            VariantTypeId::UInt64,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_int64() {
    let v: Variant = 10i64.into();
    // Boolean
    assert_eq!(v.cast(VariantTypeId::Boolean), Variant::Empty);
    assert_eq!(
        Variant::from(1i64).cast(VariantTypeId::Boolean),
        Variant::from(true)
    );
    // Byte
    assert_eq!(v.cast(VariantTypeId::Byte), Variant::from(10u8));
    assert_eq!(
        Variant::from(-120i64).cast(VariantTypeId::Byte),
        Variant::Empty
    );
    // Int16
    assert_eq!(v.cast(VariantTypeId::Int16), Variant::from(10i16));
    // SByte
    assert_eq!(v.cast(VariantTypeId::SByte), Variant::from(10i8));
    assert_eq!(
        Variant::from(-137i64).cast(VariantTypeId::SByte),
        Variant::Empty
    );
    // StatusCode
    let status_code = StatusCode::BadResourceUnavailable
        | StatusCode::HISTORICAL_RAW
        | StatusCode::SEMANTICS_CHANGED;
    assert_eq!(
        Variant::from(status_code.bits() as i64).cast(VariantTypeId::StatusCode),
        Variant::from(status_code)
    );
    // String
    assert_eq!(v.cast(VariantTypeId::String), Variant::from("10"));
    // UInt16
    assert_eq!(v.cast(VariantTypeId::UInt16), Variant::from(10u16));
    assert_eq!(
        Variant::from(-120i64).cast(VariantTypeId::UInt16),
        Variant::Empty
    );
    // UInt32
    assert_eq!(v.cast(VariantTypeId::UInt32), Variant::from(10u32));
    assert_eq!(
        Variant::from(-120i64).cast(VariantTypeId::UInt32),
        Variant::Empty
    );
    // UInt64
    assert_eq!(v.cast(VariantTypeId::UInt64), Variant::from(10u64));
    assert_eq!(
        Variant::from(-120i64).cast(VariantTypeId::UInt32),
        Variant::Empty
    );
}

#[test]
fn variant_convert_sbyte() {
    let v: Variant = 12i8.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(v.convert(VariantTypeId::Double), Variant::Double(12.0));
    assert_eq!(v.convert(VariantTypeId::Float), Variant::Float(12.0));
    assert_eq!(v.convert(VariantTypeId::Int16), Variant::Int16(12));
    assert_eq!(v.convert(VariantTypeId::Int32), Variant::Int32(12));
    assert_eq!(v.convert(VariantTypeId::Int64), Variant::Int64(12));
    assert_eq!(v.convert(VariantTypeId::UInt16), Variant::UInt16(12));
    assert_eq!(v.convert(VariantTypeId::UInt32), Variant::UInt32(12));
    assert_eq!(v.convert(VariantTypeId::UInt64), Variant::UInt64(12));
    // Impermissible
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::Boolean,
            VariantTypeId::Byte,
            VariantTypeId::ByteString,
            VariantTypeId::DateTime,
            VariantTypeId::ExpandedNodeId,
            VariantTypeId::Guid,
            VariantTypeId::NodeId,
            VariantTypeId::StatusCode,
            VariantTypeId::String,
            VariantTypeId::LocalizedText,
            VariantTypeId::QualifiedName,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_sbyte() {
    let v: Variant = 12i8.into();
    // Boolean
    assert_eq!(v.cast(VariantTypeId::Boolean), Variant::Empty);
    assert_eq!(
        Variant::from(1i8).cast(VariantTypeId::Boolean),
        Variant::from(true)
    );
    // Byte
    assert_eq!(v.cast(VariantTypeId::Byte), Variant::from(12u8));
    assert_eq!(
        Variant::from(-120i8).cast(VariantTypeId::Byte),
        Variant::Empty
    );
    // String
    assert_eq!(v.cast(VariantTypeId::String), Variant::from("12"));
}

#[test]
fn variant_convert_string() {
    let v = Variant::from("Reflexive Test");
    assert_eq!(v.convert(v.type_id()), v);
    // Boolean
    assert_eq!(
        Variant::from("1").convert(VariantTypeId::Boolean),
        true.into()
    );
    assert_eq!(
        Variant::from("0").convert(VariantTypeId::Boolean),
        false.into()
    );
    assert_eq!(
        Variant::from("true").convert(VariantTypeId::Boolean),
        true.into()
    );
    assert_eq!(
        Variant::from("false").convert(VariantTypeId::Boolean),
        false.into()
    );
    assert_eq!(
        Variant::from(" false").convert(VariantTypeId::Boolean),
        Variant::Empty
    );
    // Byte
    assert_eq!(
        Variant::from("12").convert(VariantTypeId::Byte),
        12u8.into()
    );
    assert_eq!(
        Variant::from("256").convert(VariantTypeId::Byte),
        Variant::Empty
    );
    // Double
    assert_eq!(
        Variant::from("12.5").convert(VariantTypeId::Double),
        12.5f64.into()
    );
    // Float
    assert_eq!(
        Variant::from("12.5").convert(VariantTypeId::Float),
        12.5f32.into()
    );
    // Guid
    assert_eq!(
        Variant::from("d47a32c9-5ee7-43c1-a733-0fe30bf26b50").convert(VariantTypeId::Guid),
        Guid::from_str("d47a32c9-5ee7-43c1-a733-0fe30bf26b50")
            .unwrap()
            .into()
    );
    // Int16
    assert_eq!(
        Variant::from("12").convert(VariantTypeId::Int16),
        12i16.into()
    );
    assert_eq!(
        Variant::from("65536").convert(VariantTypeId::Int16),
        Variant::Empty
    );
    // Int32
    assert_eq!(
        Variant::from("12").convert(VariantTypeId::Int32),
        12i32.into()
    );
    assert_eq!(
        Variant::from("2147483648").convert(VariantTypeId::Int32),
        Variant::Empty
    );
    // Int64
    assert_eq!(
        Variant::from("12").convert(VariantTypeId::Int64),
        12i64.into()
    );
    assert_eq!(
        Variant::from("9223372036854775808").convert(VariantTypeId::Int64),
        Variant::Empty
    );
    // SByte
    assert_eq!(
        Variant::from("12").convert(VariantTypeId::SByte),
        12i8.into()
    );
    assert_eq!(
        Variant::from("128").convert(VariantTypeId::SByte),
        Variant::Empty
    );
    assert_eq!(
        Variant::from("-129").convert(VariantTypeId::SByte),
        Variant::Empty
    );
    // UInt16
    assert_eq!(
        Variant::from("12").convert(VariantTypeId::UInt16),
        12u16.into()
    );
    assert_eq!(
        Variant::from("65536").convert(VariantTypeId::UInt16),
        Variant::Empty
    );
    // UInt32
    assert_eq!(
        Variant::from("12").convert(VariantTypeId::UInt32),
        12u32.into()
    );
    assert_eq!(
        Variant::from("4294967296").convert(VariantTypeId::UInt32),
        Variant::Empty
    );
    // UInt64
    assert_eq!(
        Variant::from("12").convert(VariantTypeId::UInt64),
        12u64.into()
    );
    assert_eq!(
        Variant::from("18446744073709551615").convert(VariantTypeId::UInt32),
        Variant::Empty
    );
    // Impermissible
    let v = Variant::from("xxx");
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::ByteString,
            VariantTypeId::StatusCode,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_string() {
    // DateTime
    let now = DateTime::now();
    let now_s = format!("{}", now);
    let now_v: Variant = now.into();
    assert_eq!(Variant::from(now_s).cast(VariantTypeId::DateTime), now_v);
    // ExpandedNodeId
    assert_eq!(
        Variant::from("svr=5;ns=22;s=Hello World").cast(VariantTypeId::ExpandedNodeId),
        ExpandedNodeId {
            node_id: NodeId::new(22, "Hello World"),
            namespace_uri: UAString::null(),
            server_index: 5,
        }
        .into()
    );
    // NodeId
    assert_eq!(
        Variant::from("ns=22;s=Hello World").cast(VariantTypeId::NodeId),
        NodeId::new(22, "Hello World").into()
    );
    // LocalizedText
    assert_eq!(
        Variant::from("Localized Text").cast(VariantTypeId::LocalizedText),
        LocalizedText::new("", "Localized Text").into()
    );
    // QualifiedName
    assert_eq!(
        Variant::from("Qualified Name").cast(VariantTypeId::QualifiedName),
        QualifiedName::new(0, "Qualified Name").into()
    );
}

#[test]
fn variant_convert_uint16() {
    let v: Variant = 80u16.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(v.convert(VariantTypeId::Double), Variant::Double(80.0));
    assert_eq!(v.convert(VariantTypeId::Float), Variant::Float(80.0));
    assert_eq!(v.convert(VariantTypeId::Int16), Variant::Int16(80));
    assert_eq!(v.convert(VariantTypeId::Int32), Variant::Int32(80));
    assert_eq!(v.convert(VariantTypeId::Int64), Variant::Int64(80));
    assert_eq!(
        v.convert(VariantTypeId::StatusCode),
        Variant::StatusCode(StatusCode::from_bits_truncate(80 << 16))
    );
    assert_eq!(v.convert(VariantTypeId::UInt32), Variant::UInt32(80));
    assert_eq!(v.convert(VariantTypeId::UInt64), Variant::UInt64(80));
    // Impermissible
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::Boolean,
            VariantTypeId::Byte,
            VariantTypeId::ByteString,
            VariantTypeId::DateTime,
            VariantTypeId::ExpandedNodeId,
            VariantTypeId::Guid,
            VariantTypeId::SByte,
            VariantTypeId::String,
            VariantTypeId::NodeId,
            VariantTypeId::LocalizedText,
            VariantTypeId::QualifiedName,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_uint16() {
    let v: Variant = 80u16.into();
    // Boolean
    assert_eq!(v.cast(VariantTypeId::Boolean), Variant::Empty);
    assert_eq!(
        Variant::from(1u16).cast(VariantTypeId::Boolean),
        Variant::from(true)
    );
    // Byte
    assert_eq!(v.cast(VariantTypeId::Byte), Variant::from(80u8));
    assert_eq!(
        Variant::from(256u16).cast(VariantTypeId::Byte),
        Variant::Empty
    );
    // SByte
    assert_eq!(v.cast(VariantTypeId::SByte), Variant::from(80i8));
    assert_eq!(
        Variant::from(128u16).cast(VariantTypeId::SByte),
        Variant::Empty
    );
    // String
    assert_eq!(v.cast(VariantTypeId::String), Variant::from("80"));
}

#[test]
fn variant_convert_uint32() {
    let v: Variant = 23u32.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(v.convert(VariantTypeId::Double), Variant::Double(23.0));
    assert_eq!(v.convert(VariantTypeId::Float), Variant::Float(23.0));
    assert_eq!(v.convert(VariantTypeId::Int32), Variant::Int32(23));
    assert_eq!(v.convert(VariantTypeId::Int64), Variant::Int64(23));
    assert_eq!(v.convert(VariantTypeId::UInt32), Variant::UInt32(23));
    assert_eq!(v.convert(VariantTypeId::UInt64), Variant::UInt64(23));
    // Impermissible
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::Boolean,
            VariantTypeId::Byte,
            VariantTypeId::ByteString,
            VariantTypeId::DateTime,
            VariantTypeId::ExpandedNodeId,
            VariantTypeId::Guid,
            VariantTypeId::Int16,
            VariantTypeId::SByte,
            VariantTypeId::StatusCode,
            VariantTypeId::String,
            VariantTypeId::NodeId,
            VariantTypeId::LocalizedText,
            VariantTypeId::QualifiedName,
            VariantTypeId::UInt16,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_uint32() {
    let v: Variant = 23u32.into();
    // Boolean
    assert_eq!(v.cast(VariantTypeId::Boolean), Variant::Empty);
    assert_eq!(
        Variant::from(1u32).cast(VariantTypeId::Boolean),
        Variant::from(true)
    );
    // Byte
    assert_eq!(v.cast(VariantTypeId::Byte), Variant::from(23u8));
    assert_eq!(
        Variant::from(256u32).cast(VariantTypeId::Byte),
        Variant::Empty
    );
    // Int16
    assert_eq!(v.cast(VariantTypeId::Int16), Variant::from(23i16));
    assert_eq!(
        Variant::from(102256u32).cast(VariantTypeId::Int16),
        Variant::Empty
    );
    // SByte
    assert_eq!(v.cast(VariantTypeId::SByte), Variant::from(23i8));
    assert_eq!(
        Variant::from(128u32).cast(VariantTypeId::SByte),
        Variant::Empty
    );
    // StatusCode
    let status_code = StatusCode::BadResourceUnavailable
        | StatusCode::HISTORICAL_RAW
        | StatusCode::SEMANTICS_CHANGED;
    assert_eq!(
        Variant::from(status_code.bits() as u32).cast(VariantTypeId::StatusCode),
        Variant::from(status_code)
    );
    // String
    assert_eq!(v.cast(VariantTypeId::String), Variant::from("23"));
    // UInt16
    assert_eq!(v.cast(VariantTypeId::UInt16), Variant::from(23u16));
    assert_eq!(
        Variant::from(102256u32).cast(VariantTypeId::UInt16),
        Variant::Empty
    );
}

#[test]
fn variant_convert_uint64() {
    let v: Variant = 43u64.into();
    assert_eq!(v.convert(v.type_id()), v);
    // All these are implicit conversions expected to succeed
    assert_eq!(v.convert(VariantTypeId::Double), Variant::Double(43.0));
    assert_eq!(v.convert(VariantTypeId::Float), Variant::Float(43.0));
    assert_eq!(v.convert(VariantTypeId::Int64), Variant::Int64(43));
    assert_eq!(v.convert(VariantTypeId::UInt64), Variant::UInt64(43));
    // Impermissible
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::Boolean,
            VariantTypeId::Byte,
            VariantTypeId::ByteString,
            VariantTypeId::DateTime,
            VariantTypeId::ExpandedNodeId,
            VariantTypeId::Guid,
            VariantTypeId::Int16,
            VariantTypeId::Int32,
            VariantTypeId::SByte,
            VariantTypeId::StatusCode,
            VariantTypeId::String,
            VariantTypeId::NodeId,
            VariantTypeId::LocalizedText,
            VariantTypeId::QualifiedName,
            VariantTypeId::UInt16,
            VariantTypeId::UInt32,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_uint64() {
    let v: Variant = 43u64.into();
    // Boolean
    assert_eq!(v.cast(VariantTypeId::Boolean), Variant::Empty);
    assert_eq!(
        Variant::from(1u64).cast(VariantTypeId::Boolean),
        Variant::from(true)
    );
    // Byte
    assert_eq!(v.cast(VariantTypeId::Byte), Variant::from(43u8));
    assert_eq!(
        Variant::from(256u64).cast(VariantTypeId::Byte),
        Variant::Empty
    );
    // Int16
    assert_eq!(v.cast(VariantTypeId::Int16), Variant::from(43i16));
    assert_eq!(
        Variant::from(102256u64).cast(VariantTypeId::Int16),
        Variant::Empty
    );
    // SByte
    assert_eq!(v.cast(VariantTypeId::SByte), Variant::from(43i8));
    assert_eq!(
        Variant::from(128u64).cast(VariantTypeId::SByte),
        Variant::Empty
    );
    // StatusCode
    let status_code = StatusCode::BadResourceUnavailable
        | StatusCode::HISTORICAL_RAW
        | StatusCode::SEMANTICS_CHANGED;
    assert_eq!(
        Variant::from(status_code.bits() as u64).cast(VariantTypeId::StatusCode),
        Variant::from(status_code)
    );
    // String
    assert_eq!(v.cast(VariantTypeId::String), Variant::from("43"));
    // UInt16
    assert_eq!(v.cast(VariantTypeId::UInt16), Variant::from(43u16));
    assert_eq!(
        Variant::from(102256u64).cast(VariantTypeId::UInt16),
        Variant::Empty
    );
    // UInt32
    assert_eq!(v.cast(VariantTypeId::UInt32), Variant::from(43u32));
    assert_eq!(
        Variant::from(4294967298u64).cast(VariantTypeId::UInt32),
        Variant::Empty
    );
}

#[test]
fn variant_cast_date_time() {
    let now = DateTime::now();
    let now_s = format!("{}", now);
    assert_eq!(Variant::from(now).cast(VariantTypeId::String), now_s.into());
}

#[test]
fn variant_convert_guid() {
    let v = Variant::from(Guid::new());
    // Impermissible
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::Boolean,
            VariantTypeId::Byte,
            VariantTypeId::ByteString,
            VariantTypeId::DateTime,
            VariantTypeId::Double,
            VariantTypeId::ExpandedNodeId,
            VariantTypeId::Float,
            VariantTypeId::Int16,
            VariantTypeId::Int32,
            VariantTypeId::Int64,
            VariantTypeId::NodeId,
            VariantTypeId::SByte,
            VariantTypeId::StatusCode,
            VariantTypeId::String,
            VariantTypeId::LocalizedText,
            VariantTypeId::QualifiedName,
            VariantTypeId::UInt16,
            VariantTypeId::UInt32,
            VariantTypeId::UInt64,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_guid() {
    let g = Guid::new();
    let v = Variant::from(g.clone());
    // ByteString
    let b = ByteString::from(g.clone());
    assert_eq!(v.cast(VariantTypeId::ByteString), b.into());
    // String
    assert_eq!(v.cast(VariantTypeId::String), format!("{}", g).into());
}

#[test]
fn variant_convert_status_code() {
    let v = Variant::from(StatusCode::BadInvalidArgument);
    assert_eq!(v.convert(v.type_id()), v);
    // Implicit Int32, Int64, UInt32, UInt64
    assert_eq!(
        v.convert(VariantTypeId::Int32),
        Variant::Int32(-2136276992i32)
    ); // 0x80AB_0000 overflows to negative
    assert_eq!(v.convert(VariantTypeId::Int64), Variant::Int64(0x80AB_0000));
    assert_eq!(
        v.convert(VariantTypeId::UInt32),
        Variant::UInt32(0x80AB_0000)
    );
    assert_eq!(
        v.convert(VariantTypeId::UInt64),
        Variant::UInt64(0x80AB_0000)
    );
    // Impermissible
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::Boolean,
            VariantTypeId::Byte,
            VariantTypeId::ByteString,
            VariantTypeId::DateTime,
            VariantTypeId::Double,
            VariantTypeId::ExpandedNodeId,
            VariantTypeId::Float,
            VariantTypeId::Guid,
            VariantTypeId::Int16,
            VariantTypeId::NodeId,
            VariantTypeId::SByte,
            VariantTypeId::String,
            VariantTypeId::LocalizedText,
            VariantTypeId::QualifiedName,
            VariantTypeId::UInt16,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_status_code() {
    let status_code = StatusCode::BadResourceUnavailable
        | StatusCode::HISTORICAL_RAW
        | StatusCode::SEMANTICS_CHANGED;
    let v = Variant::from(status_code);
    // Cast UInt16 (BadResourceUnavailable == 0x8004_0000)
    assert_eq!(v.cast(VariantTypeId::UInt16), Variant::UInt16(0x8004));
}

#[test]
fn variant_convert_byte_string() {
    let v = Variant::from(ByteString::from(b"test"));
    assert_eq!(v.convert(v.type_id()), v);
    // Impermissible
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::Boolean,
            VariantTypeId::Byte,
            VariantTypeId::DateTime,
            VariantTypeId::Double,
            VariantTypeId::ExpandedNodeId,
            VariantTypeId::Float,
            VariantTypeId::Guid,
            VariantTypeId::Int16,
            VariantTypeId::Int32,
            VariantTypeId::Int64,
            VariantTypeId::NodeId,
            VariantTypeId::SByte,
            VariantTypeId::StatusCode,
            VariantTypeId::String,
            VariantTypeId::LocalizedText,
            VariantTypeId::QualifiedName,
            VariantTypeId::UInt16,
            VariantTypeId::UInt32,
            VariantTypeId::UInt64,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_byte_string() {
    let g = Guid::new();
    let v = Variant::from(ByteString::from(g.clone()));
    // Guid
    assert_eq!(v.cast(VariantTypeId::Guid), g.into());
}

#[test]
fn variant_convert_qualified_name() {
    let v = Variant::from(QualifiedName::new(123, "hello"));
    assert_eq!(v.convert(v.type_id()), v);
    // LocalizedText
    assert_eq!(
        v.convert(VariantTypeId::LocalizedText),
        Variant::from(LocalizedText::new("", "hello"))
    );
    // String
    assert_eq!(v.convert(VariantTypeId::String), Variant::from("hello"));
    // Impermissible
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::Boolean,
            VariantTypeId::Byte,
            VariantTypeId::ByteString,
            VariantTypeId::DateTime,
            VariantTypeId::Double,
            VariantTypeId::ExpandedNodeId,
            VariantTypeId::Float,
            VariantTypeId::Guid,
            VariantTypeId::Int16,
            VariantTypeId::Int32,
            VariantTypeId::Int64,
            VariantTypeId::NodeId,
            VariantTypeId::SByte,
            VariantTypeId::StatusCode,
            VariantTypeId::UInt16,
            VariantTypeId::UInt32,
            VariantTypeId::UInt64,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_convert_localized_text() {
    let v = Variant::from(LocalizedText::new("fr-FR", "bonjour"));
    assert_eq!(v.convert(v.type_id()), v);
    // String
    assert_eq!(v.convert(VariantTypeId::String), Variant::from("bonjour"));
    // Impermissible
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::Boolean,
            VariantTypeId::Byte,
            VariantTypeId::ByteString,
            VariantTypeId::DateTime,
            VariantTypeId::Double,
            VariantTypeId::ExpandedNodeId,
            VariantTypeId::Float,
            VariantTypeId::Guid,
            VariantTypeId::Int16,
            VariantTypeId::Int32,
            VariantTypeId::Int64,
            VariantTypeId::NodeId,
            VariantTypeId::SByte,
            VariantTypeId::StatusCode,
            VariantTypeId::QualifiedName,
            VariantTypeId::UInt16,
            VariantTypeId::UInt32,
            VariantTypeId::UInt64,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_convert_node_id() {
    let v = Variant::from(NodeId::new(99, "my node"));
    assert_eq!(v.convert(v.type_id()), v);
    // ExpandedNodeId
    assert_eq!(
        v.convert(VariantTypeId::ExpandedNodeId),
        Variant::from(ExpandedNodeId {
            node_id: NodeId::new(99, "my node"),
            namespace_uri: UAString::null(),
            server_index: 0,
        })
    );
    // String
    assert_eq!(
        v.convert(VariantTypeId::String),
        Variant::from("ns=99;s=my node")
    );
    // Impermissible
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::Boolean,
            VariantTypeId::Byte,
            VariantTypeId::ByteString,
            VariantTypeId::DateTime,
            VariantTypeId::Double,
            VariantTypeId::Float,
            VariantTypeId::Guid,
            VariantTypeId::Int16,
            VariantTypeId::Int32,
            VariantTypeId::Int64,
            VariantTypeId::SByte,
            VariantTypeId::LocalizedText,
            VariantTypeId::QualifiedName,
            VariantTypeId::UInt16,
            VariantTypeId::UInt32,
            VariantTypeId::UInt64,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_convert_expanded_node_id() {
    let v = Variant::from(ExpandedNodeId {
        node_id: NodeId::new(22, "Hello World"),
        namespace_uri: UAString::null(),
        server_index: 5,
    });
    assert_eq!(v.convert(v.type_id()), v);
    // String
    assert_eq!(
        v.convert(VariantTypeId::String),
        Variant::from("svr=5;ns=22;s=Hello World")
    );
    // Impermissible
    ensure_conversion_fails(
        &v,
        &[
            VariantTypeId::Boolean,
            VariantTypeId::Byte,
            VariantTypeId::ByteString,
            VariantTypeId::DateTime,
            VariantTypeId::Double,
            VariantTypeId::Float,
            VariantTypeId::Guid,
            VariantTypeId::Int16,
            VariantTypeId::Int32,
            VariantTypeId::Int64,
            VariantTypeId::NodeId,
            VariantTypeId::SByte,
            VariantTypeId::LocalizedText,
            VariantTypeId::QualifiedName,
            VariantTypeId::UInt16,
            VariantTypeId::UInt32,
            VariantTypeId::UInt64,
            VariantTypeId::XmlElement,
        ],
    );
}

#[test]
fn variant_cast_expanded_node_id() {
    let v = Variant::from(ExpandedNodeId {
        node_id: NodeId::new(22, "Hello World"),
        namespace_uri: UAString::null(),
        server_index: 5,
    });
    // NodeId
    assert_eq!(
        v.cast(VariantTypeId::NodeId),
        Variant::from(NodeId::new(22, "Hello World"))
    );
}

#[test]
fn variant_bytestring_to_bytearray() {
    let v = ByteString::from(&[0x1, 0x2, 0x3, 0x4]);
    let v = Variant::from(v);

    let v = v.to_byte_array().unwrap();
    assert_eq!(v.array_data_type().unwrap(), DataTypeId::Byte.into());

    let array = match v {
        Variant::Array(v) => v,
        _ => panic!(),
    };

    let v = array.values;
    assert_eq!(v.len(), 4);
    assert_eq!(v[0], Variant::Byte(0x1));
    assert_eq!(v[1], Variant::Byte(0x2));
    assert_eq!(v[2], Variant::Byte(0x3));
    assert_eq!(v[3], Variant::Byte(0x4));
}

// TODO arrays
