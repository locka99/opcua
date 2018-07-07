use variant::{Variant, VariantTypeId, MultiDimensionArray};

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
fn variant_type_id() {
    use {UAString, DateTime, ByteString, XmlElement, NodeId, ExpandedNodeId, QualifiedName, LocalizedText, ExtensionObject, DataValue, Guid};
    use status_codes::StatusCode;

    let types = [
        (Variant::Empty, VariantTypeId::Empty),
        (Variant::Boolean(true), VariantTypeId::Boolean),
        (Variant::SByte(0i8), VariantTypeId::SByte),
        (Variant::Byte(0u8), VariantTypeId::Byte),
        (Variant::Int16(0i16), VariantTypeId::Int16),
        (Variant::UInt16(0u16), VariantTypeId::UInt16),
        (Variant::Int32(0i32), VariantTypeId::Int32),
        (Variant::UInt32(0u32), VariantTypeId::UInt32),
        (Variant::Int64(0i64), VariantTypeId::Int64),
        (Variant::UInt64(0u64), VariantTypeId::UInt64),
        (Variant::Float(0f32), VariantTypeId::Float),
        (Variant::Double(0f64), VariantTypeId::Double),
        (Variant::String(UAString::null()), VariantTypeId::String),
        (Variant::DateTime(DateTime::now()), VariantTypeId::DateTime),
        (Variant::Guid(Guid::new()), VariantTypeId::Guid),
        (Variant::ByteString(ByteString::null()), VariantTypeId::ByteString),
        (Variant::XmlElement(XmlElement::null()), VariantTypeId::XmlElement),
        (Variant::NodeId(Box::new(NodeId::null())), VariantTypeId::NodeId),
        (Variant::ExpandedNodeId(Box::new(ExpandedNodeId::null())), VariantTypeId::ExpandedNodeId),
        (Variant::StatusCode(StatusCode::Good), VariantTypeId::StatusCode),
        (Variant::QualifiedName(Box::new(QualifiedName::null())), VariantTypeId::QualifiedName),
        (Variant::LocalizedText(Box::new(LocalizedText::null())), VariantTypeId::LocalizedText),
        (Variant::ExtensionObject(Box::new(ExtensionObject::null())), VariantTypeId::ExtensionObject),
        (Variant::DataValue(Box::new(DataValue::null())), VariantTypeId::DataValue),
        (Variant::Array(vec![]), VariantTypeId::Array),
        (Variant::MultiDimensionArray(Box::new(MultiDimensionArray::new(vec![], vec![1]))), VariantTypeId::MultiDimensionArray),
    ];
    for t in &types {
        assert_eq!(t.0.type_id(), t.1);
    }
}

#[test]
fn variant_u32_array() {
    let v = Variant::from_u32_array(&[1, 2, 3]);
    assert!(v.is_array());
    assert!(v.is_numeric_array());
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
fn variant_i32_array() {
    let v = Variant::from_i32_array(&[1, 2, 3]);
    assert!(v.is_array());
    assert!(v.is_numeric_array());
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
    assert!(!v.is_numeric_array());
    assert!(!v.is_valid());
}

#[test]
fn variant_multi_dimensional_array() {
    let v = Variant::from(MultiDimensionArray::new(vec![Variant::from(10)], vec![1]));
    assert!(v.is_array());
    assert!(v.is_numeric_array());
    assert!(v.is_valid());

    let v = Variant::from(MultiDimensionArray::new(vec![Variant::from(10), Variant::from(10)], vec![2]));
    assert!(v.is_array());
    assert!(v.is_numeric_array());
    assert!(v.is_valid());

    let v = Variant::from(MultiDimensionArray::new(vec![Variant::from(10), Variant::from(10)], vec![1, 2]));
    assert!(v.is_array());
    assert!(v.is_numeric_array());
    assert!(v.is_valid());

    let v = Variant::from(MultiDimensionArray::new(vec![Variant::from(10), Variant::from(10)], vec![1, 2, 3]));
    assert!(v.is_array());
    assert!(v.is_numeric_array());
    assert!(!v.is_valid());
}