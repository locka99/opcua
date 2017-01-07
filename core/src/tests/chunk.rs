use types::*;
use comms::*;
use services::*;

use super::*;

struct Test;

impl Test {
    pub fn setup() -> Test {
        let _ = ::init_logging();
        Test {}
    }
}


fn get_sample_data_security_none() -> Vec<u8> {
    return vec![
        0x2f, 0x00, 0x00, 0x00, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x70, 0x63, 0x66,
        0x6f, 0x75, 0x6e, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x6f, 0x72, 0x67, 0x2f, 0x55,
        0x41, 0x2f, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x50, 0x6f, 0x6c, 0x69, 0x63,
        0x79, 0x23, 0x4e, 0x6f, 0x6e, 0x65, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0xbe, 0x01, 0x00, 0x00, 0x20, 0x9b,
        0xa2, 0xfa, 0xcc, 0x65, 0xd2, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
        0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x40, 0x9c, 0x00, 0x00];
}

fn get_sample_chunk() -> Chunk {
    let sample_data = get_sample_data_security_none();
    let sample_data_len = sample_data.len() as u32;
    Chunk {
        chunk_header: ChunkHeader {
            message_type: ChunkMessageType::OpenSecureChannel,
            is_final: ChunkType::Final,
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

    let chunk = get_sample_chunk();
    let chunks = vec![chunk];

    let request = chunker.decode_open_secure_channel_request(&chunks).unwrap();
    {
        let ref request_header = request.request_header;
        assert_eq!(request_header.timestamp.ticks(), 131279270199860000);
        assert_eq!(request_header.request_handle, 1);
        assert_eq!(request_header.return_diagnostics, 0);
        assert_eq!(request_header.audit_entry_id.is_null(), true);
        assert_eq!(request_header.timeout_hint, 0);
    }

    // Encode the message up again to chunks, decode and compare to original
    let secure_channel_info = SecureChannelInfo {
        security_policy: SecurityPolicy::None,
        secure_channel_id: 1,
    } ;
    let chunks = chunker.encode(1, &secure_channel_info, &SupportedMessage::OpenSecureChannelRequest(request.clone())).unwrap();
    assert_eq!(chunks.len(), 1);
    let new_request = chunker.decode_open_secure_channel_request(&chunks).unwrap();
    assert_eq!(request, new_request);
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
            audit_entry_id: UAString::null_string(),
            timeout_hint: 123456,
            additional_header: ExtensionObject::null(), // from_str(NodeId::new_numeric(0, 222), "this is a header of some sort"),
        },
        client_protocol_version: 77,
        request_type: SecurityTokenRequestType::Renew,
        security_mode: MessageSecurityMode::SignAndEncrypt,
        client_nonce: ByteString::null_string(),
        requested_lifetime: 4664,
    };
    let new_open_secure_channel_request = serialize_test_and_return(open_secure_channel_request.clone());
    assert_eq!(open_secure_channel_request, new_open_secure_channel_request);

    // And the response
    let open_secure_channel_response = OpenSecureChannelResponse{
        response_header: ResponseHeader {
            timestamp: DateTime::now(),
            request_handle: 444,
            service_result: BAD_PROTOCOL_VERSION_UNSUPPORTED.clone(),
            service_diagnostics: DiagnosticInfo::new(),
            string_table: UAString::null_string(),
            additional_header: ExtensionObject::null(),
        },
        security_token: ChannelSecurityToken {
            secure_channel_id: 1,
            token_id: 2,
            created_at: DateTime::now(),
            revised_lifetime: 777f64,
        },
        channel_id: ByteString::from_str("abc"),
        token_id: ByteString::from_str("xyz"),
        created_at: DateTime::now(),
        revised_lifetime: 999.999f64,
        server_nonce: ByteString::from_str("jhkjdshfkjhsdkfj"),
    };
    let new_open_secure_channel_response = serialize_test_and_return(open_secure_channel_response.clone());
    assert_eq!(open_secure_channel_response, new_open_secure_channel_response);
}