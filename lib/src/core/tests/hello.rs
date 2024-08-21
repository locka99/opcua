use crate::types::{
    byte_string::ByteString,
    service_types::{ApplicationDescription, EndpointDescription, MessageSecurityMode},
    string::UAString,
};

use crate::core::comms::tcp_types::{HelloMessage, MessageHeader, MessageType};

#[test]
fn endpoint_url() {
    // Ensure hello with None endpoint is invalid
    // Ensure hello with URL > 4096 chars is invalid
    let mut h = HelloMessage {
        message_header: MessageHeader {
            message_type: MessageType::Invalid,
            message_size: 0,
        },
        protocol_version: 0,
        receive_buffer_size: 0,
        send_buffer_size: 0,
        max_message_size: 0,
        max_chunk_count: 0,
        endpoint_url: UAString::null(),
    };

    let endpoints = vec![EndpointDescription {
        endpoint_url: UAString::from("opc.tcp://foo"),
        security_policy_uri: UAString::null(),
        security_mode: MessageSecurityMode::None,
        server: ApplicationDescription::default(),
        security_level: 0,
        server_certificate: ByteString::null(),
        transport_profile_uri: UAString::null(),
        user_identity_tokens: None,
    }];

    // Negative tests
    assert!(!h.matches_endpoint(&endpoints));
    h.endpoint_url = UAString::from("");
    assert!(!h.matches_endpoint(&endpoints));
    h.endpoint_url = UAString::from("opc.tcp://foo/blah");
    assert!(!h.matches_endpoint(&endpoints));
    // 4097 bytes
    h.endpoint_url = UAString::from((0..4097).map(|_| 'A').collect::<String>());
    assert!(!h.is_endpoint_valid_length());

    // Positive tests
    h.endpoint_url = UAString::from("opc.tcp://foo/");
    assert!(h.matches_endpoint(&endpoints));
    h.endpoint_url = UAString::from("opc.tcp://bar/"); // Ignore hostname
    assert!(h.matches_endpoint(&endpoints));
    h.endpoint_url = UAString::from((0..4096).map(|_| 'A').collect::<String>());
    assert!(h.is_endpoint_valid_length())
}

#[test]
fn valid_buffer_sizes() {
    // Test that invalid buffer sizes are rejected, while valid buffer sizes are accepted
    let mut h = HelloMessage {
        message_header: MessageHeader {
            message_type: MessageType::Invalid,
            message_size: 0,
        },
        protocol_version: 0,
        receive_buffer_size: 0,
        send_buffer_size: 0,
        max_message_size: 0,
        max_chunk_count: 0,
        endpoint_url: UAString::null(),
    };
    assert!(!h.is_valid_buffer_sizes());
    h.receive_buffer_size = 8191;
    assert!(!h.is_valid_buffer_sizes());
    h.send_buffer_size = 8191;
    assert!(!h.is_valid_buffer_sizes());
    h.receive_buffer_size = 8192;
    assert!(!h.is_valid_buffer_sizes());
    h.send_buffer_size = 8192;
    assert!(h.is_valid_buffer_sizes());
}
