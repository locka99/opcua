use serde_json;

use data_value::DataValue;
use variant::Variant;
use guid::Guid;
use date_time::DateTime;
use status_codes::StatusCode;

#[test]
fn serialize_variant() {
    let v = Variant::from("Hello");
    let vs = serde_json::to_string(&v).unwrap();
    println!("v = {}", vs);
    assert_eq!(vs, r#"{"String":{"value":"Hello"}}"#);

    let guid = Guid::new();
    let guid_str = guid.to_string();
    let v = Variant::from(guid);
    let vs = serde_json::to_string(&v).unwrap();
    println!("v = {}", vs);
    assert_eq!(vs, format!("{{\"Guid\":\"{}\"}}", guid_str));

    let dt = DateTime::now();
    let dt_str = dt.to_string();
    let v = Variant::from(dt);
    let vs = serde_json::to_string(&v).unwrap();
    println!("v = {}", vs);
    assert_eq!(vs, format!("{{\"DateTime\":\"{}\"}}", dt_str));
}

#[test]
fn serialize_data_value() {
    let source_timestamp = DateTime::now();
    let server_timestamp = DateTime::now();
    let dv = DataValue {
        value: Some(Variant::from(100u16)),
        status: Some(StatusCode::BadAggregateListMismatch),
        source_timestamp: Some(source_timestamp.clone()),
        source_picoseconds: Some(123),
        server_timestamp: Some(server_timestamp.clone()),
        server_picoseconds: Some(456),
    };
    let dvs = serde_json::to_string(&dv).unwrap();
    println!("dv = {}", dvs);

    assert_eq!(dvs, format!("{{\"value\":{{\"UInt16\":100}},\"status\":\"BadAggregateListMismatch\",\"source_timestamp\":\"{}\",\"source_picoseconds\":123,\"server_timestamp\":\"{}\",\"server_picoseconds\":456}}", source_timestamp.to_string(), server_timestamp.to_string()));
}
