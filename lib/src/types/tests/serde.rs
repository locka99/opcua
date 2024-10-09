use crate::types::{
    data_value::DataValue, date_time::DateTime, guid::Guid, status_code::StatusCode,
    variant::Variant,
};

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
    let ticks = dt.checked_ticks();
    let v = Variant::from(dt);
    let vs = serde_json::to_string(&v).unwrap();
    println!("v = {}", vs);
    assert_eq!(vs, format!("{{\"DateTime\":{}}}", ticks));
}

#[test]
fn serialize_deserialize_date_time() {
    let dt1 = DateTime::now();
    let vs = serde_json::to_string(&dt1).unwrap();
    println!("date_time = {}", vs);
    let dt2 = serde_json::from_str::<DateTime>(&vs).unwrap();
    assert_eq!(dt1, dt2);
}

#[test]
fn serialize_deserialize_guid() {
    let g1 = Guid::new();
    let vs = serde_json::to_string(&g1).unwrap();
    println!("guid = {}", vs);
    let g2: Guid = serde_json::from_str(&vs).unwrap();
    assert_eq!(g1, g2);
}

#[test]
fn serialize_data_value() {
    let source_timestamp = DateTime::now();
    let server_timestamp = DateTime::now();
    let dv = DataValue {
        value: Some(Variant::from(100u16)),
        status: Some(StatusCode::BadAggregateListMismatch),
        source_timestamp: Some(source_timestamp),
        source_picoseconds: Some(123),
        server_timestamp: Some(server_timestamp),
        server_picoseconds: Some(456),
    };
    let dvs = serde_json::to_string(&dv).unwrap();
    println!("dv = {}", dvs);

    assert_eq!(dvs, format!("{{\"value\":{{\"UInt16\":100}},\"status\":2161377280,\"source_timestamp\":{},\"source_picoseconds\":123,\"server_timestamp\":{},\"server_picoseconds\":456}}", source_timestamp.checked_ticks(), server_timestamp.checked_ticks()));
}
