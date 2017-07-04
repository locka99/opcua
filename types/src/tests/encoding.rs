use ::*;
use super::*;

#[test]
fn encoding_bool() {
    serialize_test(true);
    serialize_test(false);
}

#[test]
fn encoding_sbyte() {
    serialize_test(0 as SByte);
    serialize_test(100 as SByte);
    serialize_test(-90 as SByte);
}

#[test]
fn encoding_byte() {
    serialize_test(0 as Byte);
    serialize_test(255 as Byte);
    serialize_test(90 as Byte);
}

#[test]
fn encoding_int16() {
    serialize_test(0 as Int16);
    serialize_test(-17000 as Int16);
    serialize_test(32000 as Int16);
}

#[test]
fn encoding_uint16() {
    serialize_test(0 as UInt16);
    serialize_test(57000 as UInt16);
    serialize_test(32000 as UInt16);
}

#[test]
fn encoding_int32() {
    serialize_test(0 as Int32);
    serialize_test(-17444000 as Int32);
    serialize_test(32004440 as Int32);
}


#[test]
fn encoding_uint32() {
    serialize_test(0 as UInt32);
    serialize_test(57055500 as UInt32);
    serialize_test(32555000 as UInt32);
}

#[test]
fn encoding_int64() {
    serialize_test(0 as Int64);
    serialize_test(-17442224000 as Int64);
    serialize_test(32022204440 as Int64);
}


#[test]
fn encoding_uint64() {
    serialize_test(0 as UInt64);
    serialize_test(57054445500 as UInt64);
    serialize_test(34442555000 as UInt64);
}

#[test]
fn encoding_f32() {
    serialize_test(0 as Float);
    serialize_test(12.4342 as Float);
    serialize_test(5686.222 as Float);
}

#[test]
fn encoding_f64() {
    serialize_test(0 as Double);
    serialize_test(12.43424324234 as Double);
    serialize_test(5686.222342342 as Double);
}

#[test]
fn encoding_string() {
    serialize_test(UAString::null());
    serialize_test(UAString::from_str("ショッピング"));
    serialize_test(UAString::from_str("This is a test"));
    serialize_test(UAString::from_str("This is a test"));
}

#[test]
fn encode_string_5224() {
    // Sample from OPCUA Part 6 - 5.2.2.4
    let expected = [0x06, 0x00, 0x00, 0x00, 0xE6, 0xB0, 0xB4, 0x42, 0x6F, 0x79];
    let input = UAString::from_str("水Boy");
    serialize_and_compare(input, &expected);
}

#[test]
fn encoding_datetime() {
    let mut now = DateTime::now();
    // Round nanos to the nearest tick to test comparison
    now.nano_sec = (now.nano_sec / 100) * 100;
    serialize_test(now);

    // TODO serialize a date below Jan 1 1601 ensure it decodes as epoch
    // TODO serialize a date after Dec 31 9999 ensure it decodes as endtimes
}

#[test]
fn encoding_guid() {
    let guid = Guid {
        data1: 0xf0001234,
        data2: 0xface,
        data3: 0xbeef,
        data4: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    };
    assert_eq!("F0001234-FACE-BEEF-0102-030405060708", format!("{:?}", guid));
    let new_guid = serialize_test_and_return(guid.clone());
    assert_eq!("F0001234-FACE-BEEF-0102-030405060708", format!("{:?}", new_guid));
    serialize_test(guid);
}

#[test]
fn encode_guid_5226() {
    // Sample from OPCUA Part 6 - 5.2.2.6
    let expected_bytes = [0x91, 0x2B, 0x96, 0x72, 0x75, 0xFA, 0xE6, 0x4A, 0x8D, 0x28, 0xB4, 0x04, 0xDC, 0x7D, 0xAF, 0x63];
    let guid = Guid {
        data1: 0x72962B91,
        data2: 0xFA75,
        data3: 0x4ae6,
        data4: [0x8D, 0x28, 0xB4, 0x04, 0xDC, 0x7D, 0xAF, 0x63],
    };
    serialize_and_compare(guid, &expected_bytes);
}

#[test]
fn node_id_2byte_numeric() {
    // Sample from OPCUA Part 6 - 5.2.2.9
    let node_id = NodeId::new_numeric(0, 0x72);
    let expected_bytes = [0x0, 0x72];
    serialize_and_compare(node_id.clone(), &expected_bytes);

    serialize_test(node_id);
}

#[test]
fn node_id_4byte_numeric() {
    // Sample from OPCUA Part 6 - 5.2.2.9
    let node_id = NodeId::new_numeric(5, 1025);
    assert!(node_id.is_numeric());
    // NOTE: Example is wrong in 1.0.3, says 0x40, not 0x4
    let expected_bytes = [0x1, 0x5, 0x1, 0x4];
    serialize_and_compare(node_id, &expected_bytes);

    // Serialize / deserialize to itself
    let node_id = NodeId::new_numeric(5, 1025);
    serialize_test(node_id);
}

#[test]
fn node_id_string_5229() {
    // Sample from OPCUA Part 6 - 5.2.2.9
    let node_id = NodeId::new_string(1, "Hot水");
    assert!(node_id.is_string());
    // NOTE: Example is wrong in 1.0.3, says 'r' instead of 'H'
    let expected_bytes = [0x03, 0x1, 0x0, 0x6, 0x0, 0x0, 0x0, 0x48, 0x6F, 0x74, 0xE6, 0xB0, 0xB4];
    serialize_and_compare(node_id.clone(), &expected_bytes);

    serialize_test(node_id);
}

#[test]
fn node_id_guid() {
    let guid = Guid {
        data1: 0x72962B91,
        data2: 0xFA75,
        data3: 0x4ae6,
        data4: [0x8D, 0x28, 0xB4, 0x04, 0xDC, 0x7D, 0xAF, 0x63],
    };
    let node_id = NodeId::new_guid(1, guid);
    assert!(node_id.is_guid());
    serialize_test(node_id);
}

#[test]
fn node_id_byte_string() {
    let node_id = NodeId::new_byte_string(30, ByteString::from_bytes(b"this is a byte string"));
    assert!(node_id.is_byte_string());
    serialize_test(node_id);
}

#[test]
fn extension_object() {
    let eo = ExtensionObject::null();
    serialize_test(eo);

    let eo = ExtensionObject {
        node_id: ObjectId::CreateSessionResponse_Encoding_DefaultBinary.as_node_id(),
        body: ExtensionObjectEncoding::ByteString(ByteString::from_bytes(b"hello world")),
    };
    serialize_test(eo);

    let eo = ExtensionObject {
        node_id: ObjectId::CreateSessionResponse_Encoding_DefaultBinary.as_node_id(),
        body: ExtensionObjectEncoding::XmlElement(XmlElement::from_str("hello world")),
    };
    serialize_test(eo);
}

#[test]
fn localized_text() {
    let t = LocalizedText {
        locale: UAString::null(),
        text: UAString::null(),
    };
    serialize_test(t);

    let t = LocalizedText {
        locale: UAString::from_str("Hello world"),
        text: UAString::null(),
    };
    serialize_test(t);

    let t = LocalizedText {
        locale: UAString::null(),
        text: UAString::from_str("Now is the winter of our discontent"),
    };
    serialize_test(t);

    let t = LocalizedText {
        locale: UAString::from_str("ABCDEFG"),
        text: UAString::from_str("Now is the winter of our discontent"),
    };
    serialize_test(t);
}

#[test]
fn expanded_node_id() {
    let node_id = ExpandedNodeId::new(&NodeId::new_numeric(200, 2000));
    serialize_test(node_id);

    let mut node_id = ExpandedNodeId::new(&NodeId::new_numeric(200, 2000));
    node_id.namespace_uri = UAString::from_str("test");
    serialize_test(node_id);

    let mut node_id = ExpandedNodeId::new(&NodeId::new_numeric(200, 2000));
    node_id.server_index = 500;
    serialize_test(node_id);

    let mut node_id = ExpandedNodeId::new(&NodeId::new_numeric(200, 2000));
    node_id.namespace_uri = UAString::from_str("test2");
    node_id.server_index = 50330;
    serialize_test(node_id);
}

#[test]
fn qualified_name() {
    let qname = QualifiedName {
        namespace_index: 100,
        name: UAString::from_str("this is a qualified name"),
    };
    serialize_test(qname);
}

#[test]
fn variant() {
    use std::mem;
    println!("Size of a variant in bytes is {}", mem::size_of::<Variant>());

    // Boolean
    let v = Variant::Boolean(true);
    serialize_test(v);
    // SByte
    let v = Variant::SByte(-44);
    serialize_test(v);
    // Byte
    let v = Variant::Byte(255);
    serialize_test(v);
    // Int16
    let v = Variant::Int16(-20000);
    serialize_test(v);
    // UInt16
    let v = Variant::UInt16(55778);
    serialize_test(v);
    // Int32
    let v = Variant::Int32(-9999999);
    serialize_test(v);
    // UInt32
    let v = Variant::UInt32(24424244);
    serialize_test(v);
    // Int64
    let v = Variant::Int64(-384747424424244);
    serialize_test(v);
    // UInt64
    let v = Variant::UInt64(9384747424422314244);
    serialize_test(v);
    // Float
    let v = Variant::Float(77.33f32);
    serialize_test(v);
    // Double
    let v = Variant::Double(99.123f64);
    serialize_test(v);
    // DateTime
    let v = Variant::DateTime(DateTime::now());
    serialize_test(v);
    // UAString
    let v = Variant::String(UAString::from_str("Hello Everybody"));
    serialize_test(v);
    // ByteString
    let v = Variant::ByteString(ByteString::from_bytes(b"Everything or nothing"));
    serialize_test(v);
    // XmlElement
    let v = Variant::XmlElement(XmlElement::from_str("The world wonders"));
    serialize_test(v);
    // NodeId(NodeId),
    let v = Variant::new_node_id(ObjectId::AddNodesItem_Encoding_DefaultBinary.as_node_id());
    serialize_test(v);
    let v = Variant::new_node_id(NodeId::new_string(99, "hello everyone"));
    serialize_test(v);
    // ExpandedNodeId
    let v = Variant::new_expanded_node_id(ExpandedNodeId::new(&ObjectId::AddNodesItem_Encoding_DefaultBinary.as_node_id()));
    serialize_test(v);
    // StatusCode
    let v = Variant::StatusCode(BAD_TCP_MESSAGE_TYPE_INVALID);
    serialize_test(v);
    // QualifiedName
    let v = Variant::new_qualified_name(QualifiedName {
        namespace_index: 100,
        name: UAString::from_str("this is a qualified name"),
    });
    serialize_test(v);
    // LocalizedText
    let v = Variant::new_localized_text(LocalizedText {
        locale: UAString::from_str("Hello everyone"),
        text: UAString::from_str("This text is localized")
    });
    serialize_test(v);
    // ExtensionObject
    let v = Variant::ExtensionObject(Box::new(ExtensionObject::null()));
    serialize_test(v);
    // DataValue
    let v = DataValue {
        value: Some(Variant::Double(1000f64)),
        status: Some(GOOD_CLAMPED),
        source_timestamp: Some(DateTime::now()),
        source_picoseconds: Some(333),
        server_timestamp: Some(DateTime::now()),
        server_picoseconds: Some(666),
    };
    serialize_test(v);
}

#[test]
fn variant_single_dimension_array() {
    let values = vec![Variant::Int32(100), Variant::Int32(200), Variant::Int32(300)];
    let v = Variant::Array(Box::new(values));
    serialize_test(v);
}

#[test]
fn variant_multi_dimension_array() {
    let values = vec![Variant::Int32(100), Variant::Int32(200), Variant::Int32(300), Variant::Int32(400), Variant::Int32(500), Variant::Int32(600)];
    let dimensions = vec![3, 2];
    let v = Variant::new_multi_dimension_array(values, dimensions);
    serialize_test(v);
}

#[test]
fn diagnostic_info() {
    let mut d = DiagnosticInfo {
        symbolic_id: None,
        namespace_uri: None,
        locale: None,
        localized_text: None,
        additional_info: None,
        inner_status_code: None,
        inner_diagnostic_info: None,
    };
    serialize_test(d.clone());

    d.symbolic_id = Some(25);

    assert_eq!(d.encoding_mask(), 0x1);

    d.namespace_uri = Some(100);
    assert_eq!(d.encoding_mask(), 0x3);

    d.localized_text = Some(120);
    assert_eq!(d.encoding_mask(), 0x7);

    d.locale = Some(110);
    assert_eq!(d.encoding_mask(), 0xf);

    d.additional_info = Some(UAString::from_str("Hello world"));
    assert_eq!(d.encoding_mask(), 0x1f);

    d.inner_status_code = Some(BAD_ARGUMENTS_MISSING);
    assert_eq!(d.encoding_mask(), 0x3f);

    serialize_test(d.clone());

    d.inner_diagnostic_info = Some(Box::new(DiagnosticInfo {
        symbolic_id: Some(99),
        namespace_uri: Some(437437),
        locale: Some(333),
        localized_text: Some(233),
        additional_info: Some(UAString::from_str("Nested diagnostic")),
        inner_status_code: Some(GOOD),
        inner_diagnostic_info: None,
    }));

    serialize_test(d.clone());
}