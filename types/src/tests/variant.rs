use std::convert::TryFrom;

use crate::variant::{Variant, VariantTypeId, MultiDimensionArray};

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
    use crate::{UAString, DateTime, ByteString, XmlElement, NodeId, ExpandedNodeId, QualifiedName, LocalizedText, ExtensionObject, DataValue, Guid};
    use crate::status_codes::StatusCode;

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
        (Variant::XmlElement(XmlElement::null()), VariantTypeId::XmlElement),
        (Variant::from(StatusCode::Good), VariantTypeId::StatusCode),
        (Variant::from(DateTime::now()), VariantTypeId::DateTime),
        (Variant::from(Guid::new()), VariantTypeId::Guid),
        (Variant::from(NodeId::null()), VariantTypeId::NodeId),
        (Variant::from(ExpandedNodeId::null()), VariantTypeId::ExpandedNodeId),
        (Variant::from(QualifiedName::null()), VariantTypeId::QualifiedName),
        (Variant::from(LocalizedText::null()), VariantTypeId::LocalizedText),
        (Variant::from(ExtensionObject::null()), VariantTypeId::ExtensionObject),
        (Variant::from(DataValue::null()), VariantTypeId::DataValue),
        (Variant::from(vec![1]), VariantTypeId::Array),
        (Variant::from(MultiDimensionArray::new(vec![], vec![1])), VariantTypeId::MultiDimensionArray),
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
        Variant::Array(v) => {
            assert_eq!(v.len(), 3);
            let mut i = 1u32;
            for v in v {
                assert!(v.is_numeric());
                match v {
                    Variant::UInt32(v) => {
                        assert_eq!(v, i);
                    }
                    _ => panic!("Not the expected type")
                }
                i += 1;
            }
        }
        _ => panic!("Not an array")
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
        Variant::Array(v) => {
            assert_eq!(v.len(), 3);
            let mut i = 1;
            for v in v {
                assert!(v.is_numeric());
                match v {
                    Variant::Int32(v) => {
                        assert_eq!(v, i);
                    }
                    _ => panic!("Not the expected type")
                }
                i += 1;
            }
        }
        _ => panic!("Not an array")
    }
}

#[test]
fn variant_invalid_array() {
    let v = Variant::Array(vec![Variant::from(10), Variant::from("hello")]);
    assert!(v.is_array());
    assert!(!v.is_array_of_type(VariantTypeId::Int32));
    assert!(!v.is_array_of_type(VariantTypeId::String));
    assert!(!v.is_valid());
}

#[test]
fn variant_multi_dimensional_array() {
    let v = Variant::from(MultiDimensionArray::new(vec![Variant::from(10)], vec![1]));
    assert!(v.is_array());
    assert!(v.is_array_of_type(VariantTypeId::Int32));
    assert!(v.is_valid());

    let v = Variant::from(MultiDimensionArray::new(vec![Variant::from(10), Variant::from(10)], vec![2]));
    assert!(v.is_array());
    assert!(v.is_array_of_type(VariantTypeId::Int32));
    assert!(v.is_valid());

    let v = Variant::from(MultiDimensionArray::new(vec![Variant::from(10), Variant::from(10)], vec![1, 2]));
    assert!(v.is_array());
    assert!(v.is_array_of_type(VariantTypeId::Int32));
    assert!(v.is_valid());

    let v = Variant::from(MultiDimensionArray::new(vec![Variant::from(10), Variant::from(10)], vec![1, 2, 3]));
    assert!(v.is_array());
    assert!(v.is_array_of_type(VariantTypeId::Int32));
    assert!(!v.is_valid());
}