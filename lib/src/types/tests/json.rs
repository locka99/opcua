use std::str::FromStr;

use serde_json::json;

use crate::types::{
    data_value::DataValue, date_time::DateTime, guid::Guid, status_codes::StatusCode,
    string::UAString, variant::Variant,
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
fn serialize_variant() {
    let v = Variant::from("Hello");
    let vs = serde_json::to_string(&v).unwrap();
    println!("v = {}", vs);
    assert_eq!(vs, r#"{"Type":12,"Body":"Hello"}"#);

    let guid = Guid::new();
    let guid_str = guid.to_string();
    let v = Variant::from(guid);
    let vs = serde_json::to_string(&v).unwrap();
    println!("v = {}", vs);
    assert_eq!(vs, format!("{{\"Guid\":\"{}\"}}", guid_str));

    let dt = DateTime::now();
    let ticks = dt.checked_ticks();
    let v = Variant::from(dt);
    let vs = serde_json::to_string(&v).unwrap();
    println!("v = {}", vs);
    assert_eq!(vs, format!("{{\"DateTime\":{}}}", ticks));
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
