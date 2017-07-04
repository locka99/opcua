use std::io::{Cursor};

use opcua_types::*;

use comms::*;

use super::*;

struct Test;

impl Test {
    pub fn setup() -> Test {
        let _ = ::init_logging();
        Test {}
    }
}

fn sample_secure_channel_request_data_security_none() -> Chunk {
    let sample_data = vec![
        47, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 111, 112, 99, 102, 111, 117, 110, 100, 97,
        116, 105, 111, 110, 46, 111, 114, 103, 47, 85, 65, 47, 83, 101, 99, 117, 114, 105, 116,
        121, 80, 111, 108, 105, 99, 121, 35, 78, 111, 110, 101, 255, 255, 255, 255, 255, 255,
        255, 255, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 190, 1, 0, 0, 208, 130, 196, 162, 147, 106, 210,
        1, 1, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 0, 255, 255, 255, 255, 192, 39, 9, 0];
    let sample_data_len = sample_data.len() as u32;
    Chunk {
        chunk_header: ChunkHeader {
            message_type: ChunkMessageType::OpenSecureChannel,
            chunk_type: ChunkType::Final,
            message_size: 12 + sample_data_len,
            secure_channel_id: 1,
            is_valid: true,
        },
        chunk_body: sample_data
    }
}

fn make_large_read_response() -> SupportedMessage {
    let mut results = Vec::new();
    for i in 0..10000 {
        results.push(DataValue::new(Variant::UInt32(i)));
    }
    SupportedMessage::ReadResponse(ReadResponse {
        response_header: ResponseHeader::null(),
        results: Some(results),
        diagnostic_infos: None,
    })
}

#[test]
fn chunk_multi_encode_decode() {
    let _ = Test::setup();

    let secure_channel_token = SecureChannelToken::new();
    let response = make_large_read_response();

    // Create a very large message
    let sequence_number = 1000;
    let request_id = 100;
    let chunks = Chunker::encode(sequence_number, request_id, 0, 8192, &secure_channel_token, &response).unwrap();
    assert!(chunks.len() > 1);

    // Verify chunk byte len <= 8192
    let chunk_length = chunks[0].byte_len();
    debug!("Chunk length = {}", chunk_length);
    assert!(chunk_length <= 8192);

    let new_response = Chunker::decode(&chunks, &secure_channel_token, None).unwrap();
    assert_eq!(response, new_response);
}

#[test]
fn max_message_size() {
    let _ = Test::setup();

    let secure_channel_token = SecureChannelToken::new();

    let response = make_large_read_response();

    let max_message_size = response.byte_len();

    let sequence_number = 1000;
    let request_id = 100;
    let chunks = Chunker::encode(sequence_number, request_id, max_message_size, 0, &secure_channel_token, &response).unwrap();
    assert!(chunks.len() == 1);

    // Expect this to fail
    let err = Chunker::encode(sequence_number, request_id, max_message_size - 1, 0, &secure_channel_token, &response).unwrap_err();
    assert_eq!(err, BAD_RESPONSE_TOO_LARGE);
}

#[test]
fn validate_chunk_sequences() {
    let _ = Test::setup();

    let secure_channel_token = SecureChannelToken::new();
    let response = make_large_read_response();

    // Create a very large message
    let sequence_number = 1000;
    let request_id = 100;
    let chunks = Chunker::encode(sequence_number, request_id, 0, 8192, &secure_channel_token, &response).unwrap();
    assert!(chunks.len() > 1);

    // Test sequence number is returned properly
    let result = Chunker::validate_chunk_sequences(sequence_number, &secure_channel_token, &chunks).unwrap();
    assert_eq!(sequence_number + chunks.len() as UInt32 - 1, result);

    // TODO alter seq ids to generate a BAD_SEQUENCE_NUMBER_INVALID
}

#[test]
fn chunk_open_secure_channel() {
    let _ = Test::setup();

    let chunk = sample_secure_channel_request_data_security_none();
    let chunks = vec![chunk];

    let secure_channel_token = SecureChannelToken::new();

    debug!("Decoding original chunks");
    let request = Chunker::decode(&chunks, &secure_channel_token, None).unwrap();
    let request = match request {
        SupportedMessage::OpenSecureChannelRequest(request) => request,
        _ => { panic!("Not a OpenSecureChannelRequest"); }
    };
    {
        let request_header = &request.request_header;
        assert_eq!(request_header.timestamp.ticks(), 131284521470690000);
        assert_eq!(request_header.request_handle, 1);
        assert_eq!(request_header.return_diagnostics, 0);
        assert_eq!(request_header.audit_entry_id.is_null(), true);
        assert_eq!(request_header.timeout_hint, 0);
    }

    // Encode the message up again to chunks, decode and compare to original
    debug!("Encoding back to chunks");

    let chunks = Chunker::encode(1, 1, 0, 0, &secure_channel_token, &SupportedMessage::OpenSecureChannelRequest(request.clone())).unwrap();
    assert_eq!(chunks.len(), 1);

    debug!("Decoding to compare the new version");
    let new_request = Chunker::decode(&chunks, &secure_channel_token, None).unwrap();
    let new_request = match new_request {
        SupportedMessage::OpenSecureChannelRequest(new_request) => new_request,
        _ => { panic!("Not a OpenSecureChannelRequest"); }
    };
    assert_eq!(request, new_request);
}

#[test]
fn open_secure_channel_response() {
    let chunk = vec![
        0x4f, 0x50, 0x4e, 0x46, 0x87, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00,
        0x00, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x70, 0x63, 0x66, 0x6f, 0x75, 0x6e,
        0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x6f, 0x72, 0x67, 0x2f, 0x55, 0x41, 0x2f, 0x53,
        0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x23, 0x4e,
        0x6f, 0x6e, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc1, 0x01, 0xe2, 0x50, 0x38, 0x9b, 0xa9, 0x71, 0xd2,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe2,
        0x50, 0x38, 0x9b, 0xa9, 0x71, 0xd2, 0x01, 0xc0, 0x27, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff];

    let _ = Test::setup();

    let secure_channel_token = SecureChannelToken::new();

    let mut stream = Cursor::new(chunk);
    let chunk = Chunk::decode(&mut stream).unwrap();
    let chunks = vec![chunk];

    let decoded = Chunker::decode(&chunks, &secure_channel_token, None);
    if decoded.is_err() {
        panic!("Got error {:?}", decoded.unwrap_err());
    }
    let message = Chunker::decode(&chunks, &secure_channel_token, None).unwrap();
    //debug!("message = {:#?}", message);
    let response = match message {
        SupportedMessage::OpenSecureChannelResponse(response) => response,
        _ => { panic!("Not a OpenSecureChannelResponse"); }
    };
    assert_eq!(response.response_header.request_handle, 0);
    assert_eq!(response.response_header.service_result, GOOD);
    assert_eq!(response.response_header.string_table.is_none(), true);
    assert_eq!(response.server_nonce, ByteString::null());
}

// Encode open secure channel back to itself and compare
#[test]
fn open_secure_channel() {
    let _ = Test::setup();
    let open_secure_channel_request = OpenSecureChannelRequest {
        request_header: RequestHeader {
            authentication_token: NodeId::new_numeric(0, 99),
            timestamp: DateTime::now(),
            request_handle: 1,
            return_diagnostics: 0,
            audit_entry_id: UAString::null(),
            timeout_hint: 123456,
            additional_header: ExtensionObject::null(),
        },
        client_protocol_version: 77,
        request_type: SecurityTokenRequestType::Renew,
        security_mode: MessageSecurityMode::SignAndEncrypt,
        client_nonce: ByteString::null(),
        requested_lifetime: 4664,
    };
    let new_open_secure_channel_request = serialize_test_and_return(open_secure_channel_request.clone());
    assert_eq!(open_secure_channel_request, new_open_secure_channel_request);

    // And the response
    let open_secure_channel_response = OpenSecureChannelResponse {
        response_header: ResponseHeader {
            timestamp: DateTime::now(),
            request_handle: 444,
            service_result: BAD_PROTOCOL_VERSION_UNSUPPORTED,
            service_diagnostics: DiagnosticInfo::new(),
            string_table: None,
            additional_header: ExtensionObject::null(),
        },
        server_protocol_version: 0,
        security_token: ChannelSecurityToken {
            channel_id: 1,
            token_id: 2,
            created_at: DateTime::now(),
            revised_lifetime: 777,
        },
        server_nonce: ByteString::null(),
    };
    let new_open_secure_channel_response = serialize_test_and_return(open_secure_channel_response.clone());
    assert_eq!(open_secure_channel_response, new_open_secure_channel_response);
}