use std::io::{Cursor, Write};

use opcua_types::*;

use comms::*;
use crypto::SecurityPolicy;

use tests::*;

struct Test;

impl Test {
    pub fn setup() -> Test {
        ::init_logging(::LogLevelFilter::Debug);
        Test {}
    }
}

fn sample_secure_channel_request_data_security_none() -> MessageChunk {
    let sample_data = vec![
        47, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 111, 112, 99, 102, 111, 117, 110, 100, 97,
        116, 105, 111, 110, 46, 111, 114, 103, 47, 85, 65, 47, 83, 101, 99, 117, 114, 105, 116,
        121, 80, 111, 108, 105, 99, 121, 35, 78, 111, 110, 101, 255, 255, 255, 255, 255, 255,
        255, 255, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 190, 1, 0, 0, 208, 130, 196, 162, 147, 106, 210,
        1, 1, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 0, 255, 255, 255, 255, 192, 39, 9, 0];

    let data = vec![0u8; 12 + sample_data.len()];
    let mut stream = Cursor::new(data);

    // Write a header and the sample request
    let _ = MessageChunkHeader {
        message_type: MessageChunkType::OpenSecureChannel,
        is_final: MessageIsFinalType::Final,
        message_size: 12 + sample_data.len() as u32,
        secure_channel_id: 1,
        is_valid: true,
    }.encode(&mut stream);
    let _ = stream.write(&sample_data);

    // Decode chunk from stream
    stream.set_position(0);
    let chunk = MessageChunk::decode(&mut stream).unwrap();

    println!("Sample chunk info = {:?}", chunk.message_header().unwrap());

    chunk
}


fn make_open_secure_channel_response() -> OpenSecureChannelResponse {
    OpenSecureChannelResponse {
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
    }
}

fn make_sample_message() -> SupportedMessage {
    SupportedMessage::GetEndpointsRequest(GetEndpointsRequest {
        request_header: RequestHeader {
            authentication_token: NodeId::new_numeric(0, 99),
            timestamp: DateTime::now(),
            request_handle: 1,
            return_diagnostics: 0,
            audit_entry_id: UAString::null(),
            timeout_hint: 123456,
            additional_header: ExtensionObject::null(),
        },
        endpoint_url: UAString::null(),
        locale_ids: None,
        profile_uris: None,
    })
}

fn set_chunk_sequence_number(chunk: &mut MessageChunk, secure_channel: &SecureChannel, sequence_number: UInt32) -> UInt32 {
    // Read the sequence header
    let mut chunk_info = chunk.chunk_info(&secure_channel).unwrap();
    let old_sequence_number = chunk_info.sequence_header.sequence_number;
    chunk_info.sequence_header.sequence_number = sequence_number;
    // Write the sequence header out again with new value
    let mut stream = Cursor::new(&mut chunk.data[..]);
    stream.set_position(chunk_info.sequence_header_offset as u64);
    let _ = chunk_info.sequence_header.encode(&mut stream);
    old_sequence_number
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

/// Encode a very large message with a maximum chunk size and ensure that it turns into multiple chunks
/// and that the chunks can be decoded back to the original message.
#[test]
fn chunk_multi_encode_decode() {
    let _ = Test::setup();

    let secure_channel = SecureChannel::new_no_certificate_store();
    let response = make_large_read_response();

    // Create a very large message
    let sequence_number = 1000;
    let request_id = 100;
    let chunks = Chunker::encode(sequence_number, request_id, 0, 8192, &secure_channel, &response).unwrap();
    assert!(chunks.len() > 1);

    // Verify chunk byte len maxes out at == 8192
    let chunk_length = chunks[0].byte_len();
    debug!("MessageChunk length = {}", chunk_length);
    assert_eq!(chunk_length, 8192);

    let new_response = Chunker::decode(&chunks, &secure_channel, None).unwrap();
    assert_eq!(response, new_response);
}

/// Encode a large message with multiple chunks. Ensure all but the last chunk is marked intermediate
/// and the last is marked final.
#[test]
fn chunk_multi_chunk_intermediate_final() {
    let _ = Test::setup();

    let secure_channel = SecureChannel::new_no_certificate_store();
    let response = make_large_read_response();

    // Create a very large message
    let sequence_number = 1000;
    let request_id = 100;
    let chunks = Chunker::encode(sequence_number, request_id, 0, 8192, &secure_channel, &response).unwrap();
    assert!(chunks.len() > 1);

    // All chunks except the last should be intermediate, the last should be final
    for (i, chunk) in chunks.iter().enumerate() {
        let message_header = chunk.message_header().unwrap();
        if i == chunks.len() - 1 {
            assert!(message_header.is_final == MessageIsFinalType::Final);
        } else {
            assert!(message_header.is_final == MessageIsFinalType::Intermediate);
        }
    }
}

/// Encode a very large message that matches and exceeds a max message size and expect the appropriate response
#[test]
fn max_message_size() {
    let _ = Test::setup();

    let secure_channel = SecureChannel::new_no_certificate_store();

    let response = make_large_read_response();

    let max_message_size = response.byte_len();

    let sequence_number = 1000;
    let request_id = 100;
    let chunks = Chunker::encode(sequence_number, request_id, max_message_size, 0, &secure_channel, &response).unwrap();
    assert!(chunks.len() == 1);

    // Expect this to fail
    let err = Chunker::encode(sequence_number, request_id, max_message_size - 1, 0, &secure_channel, &response).unwrap_err();
    assert_eq!(err, BAD_RESPONSE_TOO_LARGE);
}

/// Encode a large message and then verify the chunks are sequential. Also test code throws error for non-sequential
/// chunks
#[test]
fn validate_chunk_sequences() {
    let _ = Test::setup();

    let secure_channel = SecureChannel::new_no_certificate_store();
    let response = make_large_read_response();

    // Create a very large message
    let sequence_number = 1000;
    let request_id = 100;
    let mut chunks = Chunker::encode(sequence_number, request_id, 0, 8192, &secure_channel, &response).unwrap();
    assert!(chunks.len() > 1);

    // Test sequence number is returned properly
    let result = Chunker::validate_chunk_sequences(sequence_number, &secure_channel, &chunks).unwrap();
    assert_eq!(sequence_number + chunks.len() as UInt32 - 1, result);

    // Hack one of the chunks to alter its seq id
    let old_sequence_nr = set_chunk_sequence_number(&mut chunks[0], &secure_channel, 1001);
    assert_eq!(Chunker::validate_chunk_sequences(sequence_number, &secure_channel, &chunks).unwrap_err(), BAD_SEQUENCE_NUMBER_INVALID);

    // Hack the nth
    set_chunk_sequence_number(&mut chunks[0], &secure_channel, old_sequence_nr);
    let _ = set_chunk_sequence_number(&mut chunks[5], &secure_channel, 1008);
    assert_eq!(Chunker::validate_chunk_sequences(sequence_number, &secure_channel, &chunks).unwrap_err(), BAD_SEQUENCE_NUMBER_INVALID);
}

/// Test creating a request, encoding it and decoding it.
#[test]
fn chunk_open_secure_channel() {
    let _ = Test::setup();

    let chunk = sample_secure_channel_request_data_security_none();
    let chunks = vec![chunk];

    let secure_channel = SecureChannel::new_no_certificate_store();

    debug!("Decoding original chunks");
    let request = Chunker::decode(&chunks, &secure_channel, None).unwrap();
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

    let chunks = Chunker::encode(1, 1, 0, 0, &secure_channel, &SupportedMessage::OpenSecureChannelRequest(request.clone())).unwrap();
    assert_eq!(chunks.len(), 1);

    debug!("Decoding to compare the new version");
    let new_request = Chunker::decode(&chunks, &secure_channel, None).unwrap();
    let new_request = match new_request {
        SupportedMessage::OpenSecureChannelRequest(new_request) => new_request,
        _ => { panic!("Not a OpenSecureChannelRequest"); }
    };
    assert_eq!(request, new_request);
}

/// Decode a captured open secure channel response and verify some fields
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

    let secure_channel = SecureChannel::new_no_certificate_store();

    let mut stream = Cursor::new(chunk);
    let chunk = MessageChunk::decode(&mut stream).unwrap();
    let chunks = vec![chunk];

    let decoded = Chunker::decode(&chunks, &secure_channel, None);
    if decoded.is_err() {
        panic!("Got error {:?}", decoded.unwrap_err());
    }
    let message = Chunker::decode(&chunks, &secure_channel, None).unwrap();
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
    let open_secure_channel_response = make_open_secure_channel_response();
    let new_open_secure_channel_response = serialize_test_and_return(open_secure_channel_response.clone());
    assert_eq!(open_secure_channel_response, new_open_secure_channel_response);
}

fn test_encrypt_decrypt(message: SupportedMessage, security_mode: MessageSecurityMode, security_policy: SecurityPolicy) {
    let mut secure_channel = SecureChannel::new_no_certificate_store();
    secure_channel.security_mode = security_mode;
    secure_channel.security_policy = security_policy;
    // Both nonces are the same because we shall be encrypting and decrypting our own blocks
    secure_channel.nonce = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    secure_channel.their_nonce = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    secure_channel.derive_keys();

    let mut chunks = Chunker::encode(1, 1, 0, 0, &secure_channel, &message).unwrap();
    assert_eq!(chunks.len(), 1);

    {
        let mut chunk = &mut chunks[0];

        let original_data = chunk.data.clone();

        let result = chunk.apply_security(&mut secure_channel);
        debug!("Result of applying security = {:?}", result);
        assert!(result.is_ok());
        let encrypted_data = chunk.data.clone();
        assert!(encrypted_data != original_data);

        let result = chunk.verify_and_remove_security(&mut secure_channel);
        debug!("Result of verifying and removing security = {:?}", result);
        assert!(result.is_ok());
    }

    let message2 = Chunker::decode(&chunks, &secure_channel, None).unwrap();
    assert_eq!(message, message2);
}

/// Create a message, encode it to a chunk, sign the chunk, verify the signature and decode back to message
#[test]
fn symmetric_sign_message_chunk_basic128rsa15() {
    // let _ = Test::setup();
    // test_encrypt_decrypt(make_sample_message(), MessageSecurityMode::Sign, SecurityPolicy::Basic128Rsa15);
}

#[test]
fn symmetric_sign_message_chunk_basic256() {
    let _ = Test::setup();
    test_encrypt_decrypt(make_sample_message(), MessageSecurityMode::Sign, SecurityPolicy::Basic256);
}

#[test]
fn symmetric_sign_message_chunk_basic256sha256() {
    let _ = Test::setup();
    test_encrypt_decrypt(make_sample_message(), MessageSecurityMode::Sign, SecurityPolicy::Basic256Sha256);
}

/// Create a message, encode it to a chunk, sign the chunk, encrypt, decrypt, verify the signature and decode back to message
#[test]
fn symmetric_sign_and_encrypt_message_chunk_basic128rsa15() {
   let _ = Test::setup();
   test_encrypt_decrypt(make_sample_message(), MessageSecurityMode::SignAndEncrypt, SecurityPolicy::Basic128Rsa15);
}

/// Create a message, encode it to a chunk, sign the chunk, encrypt, decrypt, verify the signature and decode back to message
#[test]
fn symmetric_sign_and_encrypt_message_chunk_basic256() {
    //let _ = Test::setup();
    //test_encrypt_decrypt(make_sample_message(), MessageSecurityMode::SignAndEncrypt, SecurityPolicy::Basic256);
}

/// Create a message, encode it to a chunk, sign the chunk, encrypt, decrypt, verify the signature and decode back to message
#[test]
fn symmetric_sign_and_encrypt_message_chunk_basic256sha256() {
    //let _ = Test::setup();
    //test_encrypt_decrypt(make_sample_message(), MessageSecurityMode::SignAndEncrypt, SecurityPolicy::Basic256Sha256);
}

#[test]
fn security_policy_symmetric_encrypt_decrypt() {
    // Encrypt and decrypt directly to the security policy, make sure all is well

    let security_policy = SecurityPolicy::Basic128Rsa15;
    let mut secure_channel = SecureChannel::new_no_certificate_store();
    secure_channel.security_mode = MessageSecurityMode::SignAndEncrypt;
    secure_channel.security_policy = security_policy;
    // Both nonces are the same because we shall be encrypting and decrypting our own blocks
    secure_channel.nonce = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    secure_channel.their_nonce = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    secure_channel.derive_keys();

    let src = vec![0u8; 100];
    let mut dst = vec![0u8; 200];

    let encrypted_len = secure_channel.symmetric_encrypt_and_sign(&src, 0..80, 20..100, &mut dst).unwrap();
    assert_eq!(encrypted_len, 100);

    let mut src2 = vec![0u8; 200];
    let decrypted_len = secure_channel.symmetric_decrypt_and_verify(&dst, 0..80, 20..100, &mut src2).unwrap();
    assert_eq!(decrypted_len, 100);

    // Compare the data, not the signature
    assert_eq!(&src[..80], &src2[..80]);
}