use types::*;
use comms::*;
use services::*;
use services::secure_channel::*;

use std::io::{Read, Write, Result, Cursor};

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

#[test]
fn test_chunk_open_secure_channel() {
    let _ = Test::setup();

    let mut chunker = Chunker::new();

    let chunk = sample_secure_channel_request_data_security_none();
    let chunks = vec![chunk];

    debug!("Decoding original chunks");
    let request = chunker.decode(&chunks, None).unwrap();
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
    let secure_channel_info = SecureChannelInfo {
        security_policy: SecurityPolicy::None,
        secure_channel_id: 1,
    };
    let chunks = chunker.encode(1, &secure_channel_info, &SupportedMessage::OpenSecureChannelRequest(request.clone())).unwrap();
    assert_eq!(chunks.len(), 1);

    debug!("Decoding to compare the new version");
    chunker.last_decoded_sequence_number = -1;

    let new_request = chunker.decode(&chunks, None).unwrap();
    let new_request = match new_request {
        SupportedMessage::OpenSecureChannelRequest(new_request) => new_request,
        _ => { panic!("Not a OpenSecureChannelRequest"); }
    };
    assert_eq!(request, new_request);
}

#[test]
fn test_open_secure_channel_response() {
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

    let mut stream = Cursor::new(chunk);
    let chunk = Chunk::decode(&mut stream).unwrap();

    let mut chunker = Chunker::new();
    let message = chunker.decode(&vec![chunk], None).unwrap();
}

// Encode open secure channel back to itself and compare
#[test]
fn test_open_secure_channel() {
    let _ = Test::setup();
    let open_secure_channel_request = OpenSecureChannelRequest {
        request_header: RequestHeader {
            authentication_token: SessionAuthenticationToken {
                token: NodeId::new_numeric(0, 99),
            },
            timestamp: DateTime::now(),
            request_handle: 1,
            return_diagnostics: 0,
            audit_entry_id: UAString::null(),
            timeout_hint: 123456,
            additional_header: ExtensionObject::null(), // from_str(NodeId::new_numeric(0, 222), "this is a header of some sort"),
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
            service_result: BAD_PROTOCOL_VERSION_UNSUPPORTED.clone(),
            service_diagnostics: DiagnosticInfo::new(),
            string_table: UAString::null(),
            additional_header: ExtensionObject::null(),
        },
        server_protocol_version: 0,
        security_token: ChannelSecurityToken {
            secure_channel_id: 1,
            token_id: 2,
            created_at: DateTime::now(),
            revised_lifetime: 777,
        },
        server_nonce: ByteString::from_str("jhkjdshfkjhsdkfj"),
    };
    let new_open_secure_channel_response = serialize_test_and_return(open_secure_channel_response.clone());
    assert_eq!(open_secure_channel_response, new_open_secure_channel_response);
}