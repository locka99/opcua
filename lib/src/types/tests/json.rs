use std::str::FromStr;

use serde_json::json;

use crate::types::{
    data_value::DataValue, date_time::DateTime, guid::Guid, node_id::NodeId,
    status_codes::StatusCode, string::UAString, variant::Variant, ByteString,
};

#[test]
fn serialize_string() {
    let s: UAString = serde_json::from_value(json!(null)).unwrap();
    assert!(s.is_null());

    let json = serde_json::to_string(&UAString::null()).unwrap();
    println!("null str = {}", json);
    assert_eq!(json, "null");

    let s: UAString = serde_json::from_value(json!("Hello World!")).unwrap();
    assert_eq!(s.as_ref(), "Hello World!");

    let json = serde_json::to_string(&UAString::from("Hello World!")).unwrap();
    println!("hw str = {}", json);
    assert_eq!(json, r#""Hello World!""#);

    let json = serde_json::to_string(&UAString::from("")).unwrap();
    println!("empty str = {}", json);
    assert_eq!(json, r#""""#);
}

#[test]
fn serialize_date_time() {
    let dt1 = DateTime::now();
    let vs = serde_json::to_string(&dt1).unwrap();
    println!("date_time = {}", vs);
    let dt2 = serde_json::from_str::<DateTime>(&vs).unwrap();
    assert_eq!(dt1, dt2);
}

#[test]
fn serialize_guid() {
    let g1 = Guid::new();
    let vs = serde_json::to_string(&g1).unwrap();
    println!("guid = {}", vs);
    let g2: Guid = serde_json::from_str(&vs).unwrap();
    assert_eq!(g1, g2);

    let g1: Guid = serde_json::from_value(json!("f9e561f3-351c-47a2-b969-b8d6d7226fee")).unwrap();
    let g2 = Guid::from_str("f9e561f3-351c-47a2-b969-b8d6d7226fee").unwrap();
    assert_eq!(g1, g2);

    assert!(
        serde_json::from_value::<Guid>(json!("{f9e561f3-351c-47a2-b969-b8d6d7226fee")).is_err()
    );
}

#[test]
fn serialize_data_value() {
    let source_timestamp = DateTime::now();
    let server_timestamp = DateTime::now();
    let dv1 = DataValue {
        value: Some(Variant::from(100u16)),
        status: Some(StatusCode::BadAggregateListMismatch),
        source_timestamp: Some(source_timestamp),
        source_picoseconds: Some(123),
        server_timestamp: Some(server_timestamp),
        server_picoseconds: Some(456),
    };
    let s = serde_json::to_string(&dv1).unwrap();

    let dv2 = serde_json::from_str(&s).unwrap();
    assert_eq!(dv1, dv2);
}

#[test]
fn serialize_node_id() {
    let n = NodeId::new(0, 1);
    let json = serde_json::to_value(&n).unwrap();
    assert_eq!(json, json!({"Id": 1}));
    let n2 = serde_json::from_value::<NodeId>(json).unwrap();
    assert_eq!(n, n2);
    let n3 = serde_json::from_value::<NodeId>(json!({"IdType": 0, "Id": 1})).unwrap();
    assert_eq!(n, n3);

    let n = NodeId::new(10, 5);
    let json = serde_json::to_value(&n).unwrap();
    assert_eq!(json, json!({"Id": 5, "Namespace": 10}));
    let n2 = serde_json::from_value::<NodeId>(json).unwrap();
    assert_eq!(n, n2);

    let n = NodeId::new(1, "Hello");
    let json = serde_json::to_value(&n).unwrap();
    assert_eq!(json, json!({"IdType": 1, "Id": "Hello", "Namespace": 1}));
    let n2 = serde_json::from_value::<NodeId>(json).unwrap();
    assert_eq!(n, n2);

    let guid = "995a9546-cd91-4393-b1c8-a83851f88d6a";
    let n = NodeId::new(1, Guid::from_str(guid).unwrap());
    let json = serde_json::to_value(&n).unwrap();
    assert_eq!(json, json!({"IdType": 2, "Id": guid, "Namespace": 1}));
    let n2 = serde_json::from_value::<NodeId>(json).unwrap();
    assert_eq!(n, n2);

    let bytestring = "aGVsbG8gd29ybGQ=";
    let n = NodeId::new(1, ByteString::from_base64(bytestring).unwrap());
    let json = serde_json::to_value(&n).unwrap();
    assert_eq!(json, json!({"IdType": 3, "Id": bytestring, "Namespace": 1}));
    let n2 = serde_json::from_value::<NodeId>(json).unwrap();
    assert_eq!(n, n2);

    // Missing namespace is treated as 0
    let n2 = serde_json::from_value::<NodeId>(json!({"IdType": 1, "Id": "XYZ"})).unwrap();
    assert_eq!(NodeId::new(0, "XYZ"), n2);

    // Invalid IdType
    let n = serde_json::from_value::<NodeId>(
        json!({"IdType": 5, "Id": "InvalidIdType", "Namespace": 1}),
    );
    assert!(n.is_err());

    // Missing id
    let n = serde_json::from_value::<NodeId>(json!({"IdType": 1, "Namespace": 1}));
    assert!(n.is_err());

    // Invalid string ids
    let n = serde_json::from_value::<NodeId>(json!({"IdType": 1, "Id": null, "Namespace": 1}));
    assert!(n.is_err());
    let n = serde_json::from_value::<NodeId>(json!({"IdType": 1, "Id": true, "Namespace": 1}));
    assert!(n.is_err());
    let n = serde_json::from_value::<NodeId>(json!({"IdType": 1, "Id": "", "Namespace": 1}));
    assert!(n.is_err());

    // Invalid guid
    let n = serde_json::from_value::<NodeId>(json!({"IdType": 2, "Id": null, "Namespace": 1}));
    assert!(n.is_err());
    let n = serde_json::from_value::<NodeId>(json!({"IdType": 2, "Id": "1234", "Namespace": 1}));
    assert!(n.is_err());
    let n = serde_json::from_value::<NodeId>(json!({"IdType": 2, "Id": "", "Namespace": 1}));
    assert!(n.is_err());

    // Invalid bytestring
    let n = serde_json::from_value::<NodeId>(json!({"IdType": 3, "Id": null, "Namespace": 1}));
    assert!(n.is_err());
    let n = serde_json::from_value::<NodeId>(json!({"IdType": 3, "Id": "", "Namespace": 1}));
    assert!(n.is_err());
}

#[test]
fn serialize_expanded_node_id() {
    todo!()
}

#[test]
fn serialize_byte_string() {
    todo!()
}

#[test]
fn serialize_status_code() {
    let s = serde_json::from_value::<StatusCode>(json!(0)).unwrap();
    assert_eq!(s, StatusCode::Good);

    // TODO more can go here
}

#[test]
fn serialize_extension_object() {
    todo!()
}

#[test]
fn serialize_localized_text() {
    todo!()
}

#[test]
fn serialize_diagnostic_info() {
    todo!()
}

#[test]
fn serialize_qualified_name() {
    todo!()
}

/// Serializes and deserializes a variant. The input json should match
/// what the serialized output is. In some cases, this function may not be useful
/// if the input is not the same as the output.
fn test_ser_de_variant(variant: Variant, expected: serde_json::Value) {
    // Turn the variant to a json value and compare to expected json value
    let value = serde_json::to_value(&variant).unwrap();
    println!(
        "Comparing variant as json {} to expected json {}",
        serde_json::to_string(&value).unwrap(),
        serde_json::to_string(&expected).unwrap()
    );
    assert_eq!(value, expected);
    // Parse value back to json and compare to Variant
    let value = serde_json::from_value::<Variant>(expected).unwrap();
    println!(
        "Comparing parsed variant {:?} to expected variant {:?}",
        value, variant
    );
    assert_eq!(value, variant);
}

/// Deserializes JSON into a Variant and compare to the expected value.
fn test_json_to_variant(json: serde_json::Value, expected: Variant) {
    let value = serde_json::from_value::<Variant>(json).unwrap();
    println!(
        "Comparing parsed variant {:?} to expected variant {:?}",
        value, expected
    );
    assert_eq!(value, expected);
}

// These tests ensure serialize / deserialize works with the canonical
// form and with some other input json with missing fields or
// null values that deserialize to the proper values.

#[test]
fn serialize_variant_empty() {
    // Empty (0)
    test_ser_de_variant(Variant::Empty, json!({"Type": 0}));
    test_json_to_variant(json!(null), Variant::Empty);
    test_json_to_variant(json!({"Type": 0}), Variant::Empty);
    test_json_to_variant(json!({"Type": 0, "Body": null}), Variant::Empty);
}

#[test]
fn serialize_variant_boolean() {
    // Boolean
    test_ser_de_variant(Variant::Boolean(true), json!({"Type": 1, "Body": true}));
    test_ser_de_variant(Variant::Boolean(false), json!({"Type": 1, "Body": false}));
}

#[test]
fn serialize_variant_numeric() {
    // 8, 16 and 32-bit numerics. Missing body should be treated as the default
    // numeric value, i.e. 0
    test_ser_de_variant(Variant::SByte(-1), json!({"Type": 2, "Body": -1}));
    test_json_to_variant(json!({"Type": 2}), Variant::SByte(0));
    test_ser_de_variant(Variant::Byte(1), json!({"Type": 3, "Body": 1}));
    test_json_to_variant(json!({"Type": 3}), Variant::Byte(0));
    test_ser_de_variant(Variant::Int16(-2), json!({"Type": 4, "Body": -2}));
    test_json_to_variant(json!({"Type": 4}), Variant::Int16(0));
    test_ser_de_variant(Variant::UInt16(2), json!({"Type": 5, "Body": 2}));
    test_json_to_variant(json!({"Type": 5}), Variant::UInt16(0));
    test_ser_de_variant(Variant::Int32(-3), json!({"Type": 6, "Body": -3}));
    test_json_to_variant(json!({"Type": 6}), Variant::Int32(0));
    test_ser_de_variant(Variant::UInt32(3), json!({"Type": 7, "Body": 3}));
    test_json_to_variant(json!({"Type": 7}), Variant::UInt32(0));

    // Int64 & UInt64 are encoded as strings. Missing body should be treated as the default
    // numeric value, i.e. 0
    test_ser_de_variant(Variant::Int64(-1i64), json!({"Type": 8, "Body": "-1"}));
    test_json_to_variant(json!({"Type": 8}), Variant::Int64(0));
    test_ser_de_variant(Variant::UInt64(1000u64), json!({"Type": 9, "Body": "1000"}));
    test_json_to_variant(json!({"Type": 9}), Variant::UInt64(0));
}

#[test]
fn serialize_variant_float() {
    // Missing body should be treated as the default numeric value, i.e. 0.0

    // Note Float used by test is super precise, because of rounding errors
    test_ser_de_variant(
        Variant::Float(123.45600128173828),
        json!({"Type": 10, "Body": 123.45600128173828}),
    );
    test_json_to_variant(json!({"Type": 10}), Variant::Float(0.0));

    // Test for NaN
    let v = serde_json::to_value(Variant::Float(f32::NAN)).unwrap();
    let json = json!({"Type": 10, "Body": "NaN"});
    assert_eq!(v, json);

    // This test is a bit different because assert_eq won't work since comparing NaN to itself always yields
    // false so impossible to use assert_eq!().
    let value = serde_json::from_value::<Variant>(json!({"Type": 10, "Body": "NaN"})).unwrap();
    if let Variant::Float(v) = value {
        assert!(v.is_nan())
    } else {
        assert!(false);
    }

    // Tests for Infinity
    test_ser_de_variant(
        Variant::Float(f32::INFINITY),
        json!({"Type": 10, "Body": "Infinity"}),
    );
    test_ser_de_variant(
        Variant::Float(f32::NEG_INFINITY),
        json!({"Type": 10, "Body": "-Infinity"}),
    );
}

#[test]
fn serialize_variant_double() {
    // Double
    test_ser_de_variant(
        Variant::Double(-451.001),
        json!({"Type": 11, "Body": -451.001}),
    );
    test_json_to_variant(json!({"Type": 11}), Variant::Double(0.0));

    let v = serde_json::to_value(Variant::Double(f64::NAN)).unwrap();
    let json = json!({"Type": 11, "Body": "NaN"});
    assert_eq!(v, json);

    // This test is a bit different because assert_eq won't work since comparing NaN to itself always yields
    // false so impossible to use assert_eq!().
    let value = serde_json::from_value::<Variant>(json!({"Type": 11, "Body": "NaN"})).unwrap();
    if let Variant::Double(v) = value {
        assert!(v.is_nan())
    } else {
        assert!(false);
    }

    // Tests for Infinity
    test_ser_de_variant(
        Variant::Double(f64::INFINITY),
        json!({"Type": 11, "Body": "Infinity"}),
    );
    test_ser_de_variant(
        Variant::Double(f64::NEG_INFINITY),
        json!({"Type": 11, "Body": "-Infinity"}),
    );
}

#[test]
fn serialize_variant_string() {
    // String (12)
    test_ser_de_variant(
        Variant::String(UAString::from("Hello")),
        json!({"Type": 12, "Body": "Hello"}),
    );
    test_ser_de_variant(
        Variant::String(UAString::null()),
        json!({"Type": 12, "Body": null}),
    );
    test_json_to_variant(json!({"Type": 12}), Variant::String(UAString::null()));
    test_json_to_variant(
        json!({"Type": 12, "Body": null}),
        Variant::String(UAString::null()),
    );
}

#[test]
fn serialize_variant_datetime() {
    // DateTime (13)
    let dt = DateTime::now();
    let ticks = dt.checked_ticks();
    let v = Variant::from(dt);
    let vs = serde_json::to_string(&v).unwrap();
    println!("v = {}", vs);
    assert_eq!(vs, format!("{{\"DateTime\":{}}}", ticks));
}

#[test]
fn serialize_variant_guid() {
    // Guid (14)
    let guid = Guid::new();
    test_ser_de_variant(
        Variant::Guid(Box::new(guid.clone())),
        json!({"Type": 14, "Body": guid.to_string()}),
    );
    test_ser_de_variant(
        Variant::Guid(Box::new(Guid::null())),
        json!({"Type": 14, "Body": "00000000-0000-0000-0000-000000000000"}),
    );
}

#[test]
fn serialize_variant_bytestring() {
    // ByteString (15)
    let v = ByteString::from(&[0x1, 0x2, 0x3, 0x4]);
    let base64 = v.as_base64();
    test_ser_de_variant(Variant::ByteString(v), json!({"Type": 15, "Body": base64}));
    test_ser_de_variant(
        Variant::ByteString(ByteString::null()),
        json!({"Type": 15, "Body": null}),
    );
}

#[test]
fn serialize_variant_xmlelement() {
    // TODO XmlElement (16)
    todo!()
}

#[test]
fn serialize_variant_node_id() {
    // NodeId (17)
    test_ser_de_variant(
        Variant::NodeId(Box::new(NodeId::new(5, "Hello World"))),
        json!({"Type": 17, "Body": { "IdType": 1, "Id": "Hello World", "Namespace": 5}}),
    );
}

#[test]
fn serialize_variant_expanded_node_id() {
    // TODO ExpandedNodeId (18)
    todo!()
}

#[test]
fn serialize_variant_status_code() {
    // StatusCode (19)
    test_ser_de_variant(
        Variant::StatusCode(StatusCode::Good),
        json!({"Type": 19, "Body": 0}),
    );

    test_ser_de_variant(
        Variant::StatusCode(StatusCode::BadServerHalted),
        json!({"Type": 19, "Body": 0x800E0000u32}),
    );
}

#[test]
fn serialize_variant_qualified_name() {
    // TODO QualifiedName (20)
    todo!()
}

#[test]
fn serialize_variant_localized_text() {
    // TODO LocalizedText (21)

    todo!()
}

#[test]
fn serialize_variant_extension_object() {
    // TODO ExtensionObject (22)
    todo!()
}

#[test]
fn serialize_variant_data_value() {
    // TODO DataValue (23)
    todo!()
}

#[test]
fn serialize_variant_variant() {
    // TODO Variant (24)
    todo!()
}

#[test]
fn serialize_variant_diagnostic_info() {
    // TODO DiagnosticInfo (25)
    todo!()
}

#[test]
fn serialize_variant_single_dimension_array() {
    todo!()
}

#[test]
fn serialize_variant_multi_dimension_array() {
    todo!()
}
