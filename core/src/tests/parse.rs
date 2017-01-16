use std::str::{FromStr};

use types::*;

#[test]
fn parse_node_id() {
    let node_id = NodeId::from_str("ns=99 ;i=35");
    assert_eq!(node_id.is_err(), true);
    let node_id = NodeId::from_str("ns=99;i=x");
    assert_eq!(node_id.is_err(), true);
    let node_id = NodeId::from_str("ns=99;s=");
    assert_eq!(node_id.is_err(), true);
    let node_id = NodeId::from_str("ns=;s=valid str");
    assert_eq!(node_id.is_err(), true);
    let node_id = NodeId::from_str("ns=;s=valid str");
    assert_eq!(node_id.is_err(), true);
    let node_id = NodeId::from_str("ns=65537;s=valid str");
    assert_eq!(node_id.is_err(), true);

    // Integer
    let node_id = NodeId::from_str("i=13");
    assert_eq!(node_id.is_ok(), true);
    let node_id = node_id.unwrap();
    assert_eq!(node_id.namespace, 0);
    assert_eq!(node_id.identifier, Identifier::Numeric(13));

    let node_id = NodeId::from_str("ns=99;i=35");
    assert_eq!(node_id.is_ok(), true);
    let node_id = node_id.unwrap();
    assert_eq!(node_id.namespace, 99);
    assert_eq!(node_id.identifier, Identifier::Numeric(35));

    // String
    let node_id = NodeId::from_str("ns=1;s=Hello World");
    assert_eq!(node_id.is_ok(), true);
    let node_id = node_id.unwrap();
    assert_eq!(node_id.namespace, 1);
    assert_eq!(node_id.identifier, Identifier::String(UAString::from_str("Hello World")));

    let node_id = NodeId::from_str("s=No NS this time");
    assert_eq!(node_id.is_ok(), true);
    let node_id = node_id.unwrap();
    assert_eq!(node_id.namespace, 0);
    assert_eq!(node_id.identifier, Identifier::String(UAString::from_str("No NS this time")));

    // Guid
/*    let node_id = NodeId::from_str("g=09087e75-8e5e-499b-954f-f2a9603db28a");
    assert_eq!(node_id.is_ok(), true);
    let node_id = node_id.unwrap();
    assert_eq!(node_id.namespace, 0);
    assert_eq!(node_id.identifier, Identifier::Guid(Guid::from_fields(0x09087e75, 0x8e5e, 0x499b, &[0x95, 0x4f, 0xf2, 0xa9, 0x60, 0x3d, 0xb2, 0x8a]).unwrap()));
*/
    // TODO bytestring
}