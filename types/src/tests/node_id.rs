use std::str::FromStr;

use crate::*;

#[test]
fn parse_invalid_node_id() {
    assert!(NodeId::from_str("ns=99 ;i=35").is_err());
    assert!(NodeId::from_str("ns=99;i=x").is_err());
    assert!(NodeId::from_str("ns=99;s=").is_err());
    assert!(NodeId::from_str("ns=;s=valid str").is_err());
    assert!(NodeId::from_str("ns=;g=efa38e40-f232-497a-a534-f205e800d73").is_err()); // Missing char
    assert!(NodeId::from_str("ns=65537;s=valid str").is_err());
}

#[test]
fn parse_node_id_integer() {
    // Integer
    let node_id = NodeId::from_str("i=13").unwrap();
    assert_eq!(node_id.namespace, 0);
    assert_eq!(node_id.identifier, Identifier::Numeric(13));
    assert_eq!(format!("{}", node_id), "i=13");

    let node_id = NodeId::from_str("ns=99;i=35").unwrap();
    assert_eq!(node_id.namespace, 99);
    assert_eq!(node_id.identifier, Identifier::Numeric(35));
    assert_eq!(format!("{}", node_id), "ns=99;i=35");
}

#[test]
fn parse_node_id_string() {
    // String
    let node_id = NodeId::from_str("ns=1;s=Hello World").unwrap();
    assert_eq!(node_id.namespace, 1);
    assert_eq!(node_id.identifier, Identifier::String(UAString::from("Hello World")));
    assert_eq!(format!("{}", node_id), "ns=1;s=Hello World");

    let node_id = NodeId::from_str("s=No NS this time").unwrap();
    assert_eq!(node_id.namespace, 0);
    assert_eq!(node_id.identifier, Identifier::String(UAString::from("No NS this time")));
    assert_eq!(format!("{}", node_id), "s=No NS this time");
}

#[test]
fn parse_node_id_guid() {
    // Guid (note the mixed case)
    let node_id = NodeId::from_str("g=72962B91-FA75-4ae6-8D28-B404DC7DAF63").unwrap();
    assert_eq!(node_id.namespace, 0);
    assert_eq!(node_id.identifier, Identifier::Guid(Guid::from_str("72962B91-FA75-4ae6-8D28-B404DC7DAF63").unwrap()));
    // All lower case when returned
    assert_eq!(format!("{}", node_id), "g=72962b91-fa75-4ae6-8d28-b404dc7daf63");
}

#[test]
fn parse_node_id_byte_string() {
    // ByteString (sample bytes comes from OPC UA spec)
    let node_id = NodeId::from_str("ns=1;b=M/RbKBsRVkePCePcx24oRA==").unwrap();
    assert_eq!(node_id.namespace, 1);
    assert_eq!(node_id.identifier, Identifier::ByteString(ByteString::from_base64("M/RbKBsRVkePCePcx24oRA==").unwrap()));
    // Turn byte string back to string, compare to original
    assert_eq!(format!("{}", node_id), "ns=1;b=M/RbKBsRVkePCePcx24oRA==");
}

#[test]
fn expanded_node_id() {
    // Parse expanded node ids
    assert!(ExpandedNodeId::from_str("svr=5;ns=22;s=Hello World").is_ok());
    assert!(ExpandedNodeId::from_str("svr=5;nsu=foo;s=Hello World").is_ok());

    assert!(ExpandedNodeId::from_str("svr=;nsu=foo;s=Hello World").is_err());
    assert!(ExpandedNodeId::from_str("svr=5;nsu=;s=Hello World").is_err());
    assert!(ExpandedNodeId::from_str("svr=5;ns=;s=Hello World").is_err());
    assert!(ExpandedNodeId::from_str("svr=5;ns=5;").is_err());
    assert!(ExpandedNodeId::from_str("svr=5;ns=5;x=").is_err());
    assert!(ExpandedNodeId::from_str("svr=5;ns u=foo;s=Hello World").is_err());
    assert!(ExpandedNodeId::from_str("nsu=foo;s=Hello World").is_err());
    assert!(ExpandedNodeId::from_str("svr=5;nsu=foo;ns=5;s=Hello World").is_err());
    assert!(ExpandedNodeId::from_str("svr=5;ns=5;nsu=foo;s=Hello World").is_err());

    // Test escaping from a string
    let node_id = ExpandedNodeId::from_str("svr=5;nsu=foo%3b%25;i=22").unwrap();
    assert_eq!(node_id.server_index, 5);
    assert_eq!(node_id.namespace_uri.as_ref(), "foo;%");
    assert_eq!(node_id.node_id, NodeId::from_str("i=22").unwrap());

    // Test escaping into a string
    let node_id = ExpandedNodeId {
        node_id: NodeId::from_str("ns=1;s=Hello World").unwrap(),
        namespace_uri: UAString::from("http://foo;blah%"), // Contains escaped chars ; and %
        server_index: 33, // Note this should not display because the urn is present
    };
    assert_eq!(format!("{}", node_id), "svr=33;nsu=http://foo%3bblah%25;s=Hello World");

    // Turn node into and out of a string, ensure equals itself
    let node_id = ExpandedNodeId {
        node_id: NodeId::from_str("ns=1;s=Hello World").unwrap(),
        namespace_uri: UAString::null(),
        server_index: 33,
    };
    assert_eq!(format!("{}", node_id), "svr=33;ns=1;s=Hello World");
    assert_eq!(ExpandedNodeId::from_str("svr=33;ns=1;s=Hello World").unwrap(), node_id);
}