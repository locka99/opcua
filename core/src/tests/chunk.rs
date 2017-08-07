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
        let chunk = &mut chunks[0];

        let mut encrypted_data = vec![0u8; chunk.data.len() + 4096];
        let encrypted_size = secure_channel.apply_security(&chunk, &mut encrypted_data[..]).unwrap();
        debug!("Result of applying security = {}", encrypted_size);

        // We can't strip padding, so just compare up to original length
        let chunk2 = secure_channel.verify_and_remove_security(&encrypted_data[..encrypted_size]).unwrap();

        // Why offset 12? So we don't compare message_size part which may differ when padding is added. Less than ideal
        assert_eq!(&chunk.data[12..], &chunk2.data[12..chunk.data.len()]);
    }

    let message2 = Chunker::decode(&chunks, &secure_channel, None).unwrap();
    assert_eq!(message, message2);
}

fn test_asymmetric_encrypt_decrypt(message: SupportedMessage, security_mode: MessageSecurityMode, security_policy: SecurityPolicy) {
    let mut secure_channel = SecureChannel::new_no_certificate_store();
    secure_channel.security_mode = security_mode;
    secure_channel.security_policy = security_policy;

    // Create a cert and private key pretending to be us and them
    let (our_cert, our_key) = make_test_cert();
    let (their_cert, their_key) = make_test_cert();

    // First we shall sign with our private key and encrypt with their public.
    secure_channel.cert = Some(our_cert);
    secure_channel.their_cert = Some(their_cert);
    secure_channel.private_key = Some(our_key);

    let mut chunks = Chunker::encode(1, 1, 0, 0, &secure_channel, &message).unwrap();
    assert_eq!(chunks.len(), 1);

    let chunk = &mut chunks[0];

    let mut encrypted_data = vec![0u8; chunk.data.len() + 4096];
    let encrypted_size = secure_channel.apply_security(&chunk, &mut encrypted_data[..]).unwrap();
    debug!("Result of applying security = {}", encrypted_size);

    // Now we shall try to decrypt what has been encrypted by flipping the keys around
    let tmp = secure_channel.cert;
    secure_channel.cert = secure_channel.their_cert;
    secure_channel.their_cert = tmp;
    secure_channel.private_key = Some(their_key);

    // We can't strip padding, so just compare up to original length
    let chunk2 = secure_channel.verify_and_remove_security(&encrypted_data[..encrypted_size]).unwrap();

    assert_eq!(&chunk.data[12..], &chunk2.data[12..chunk.data.len()]);
}

#[test]
fn asymmetric_sign_and_encrypt_message_chunk_basic128rsa15() {
    let _ = Test::setup();
    test_asymmetric_encrypt_decrypt(SupportedMessage::OpenSecureChannelResponse(make_open_secure_channel_response()), MessageSecurityMode::SignAndEncrypt, SecurityPolicy::Basic128Rsa15);
}

#[test]
fn asymmetric_sign_and_encrypt_message_chunk_basic256() {
    let _ = Test::setup();
    test_asymmetric_encrypt_decrypt(SupportedMessage::OpenSecureChannelResponse(make_open_secure_channel_response()), MessageSecurityMode::SignAndEncrypt, SecurityPolicy::Basic256);
}

#[test]
fn asymmetric_sign_and_encrypt_message_chunk_basic256sha256() {
    let _ = Test::setup();
    test_asymmetric_encrypt_decrypt(SupportedMessage::OpenSecureChannelResponse(make_open_secure_channel_response()), MessageSecurityMode::SignAndEncrypt, SecurityPolicy::Basic256Sha256);
}

/// Create a message, encode it to a chunk, sign the chunk, verify the signature and decode back to message
#[test]
fn symmetric_sign_message_chunk_basic128rsa15() {
    let _ = Test::setup();
    test_encrypt_decrypt(make_sample_message(), MessageSecurityMode::Sign, SecurityPolicy::Basic128Rsa15);
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
    let _ = Test::setup();
    test_encrypt_decrypt(make_sample_message(), MessageSecurityMode::SignAndEncrypt, SecurityPolicy::Basic256);
}

/// Create a message, encode it to a chunk, sign the chunk, encrypt, decrypt, verify the signature and decode back to message
#[test]
fn symmetric_sign_and_encrypt_message_chunk_basic256sha256() {
    let _ = Test::setup();
    test_encrypt_decrypt(make_sample_message(), MessageSecurityMode::SignAndEncrypt, SecurityPolicy::Basic256Sha256);
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

#[test]
fn asymmetric_decrypt_and_verify_sample_chunk() {
    use openssl::x509;
    use openssl::pkey;

    let their_cert_data = include_bytes!("test_data/their_cert.der");
    let their_cert = X509 { value: x509::X509::from_der(&their_cert_data[..]).unwrap() };

    let their_pkey_data = include_bytes!("test_data/their_private.pem");
    let their_pkey = PKey { value: pkey::PKey::private_key_from_pem(&their_pkey_data[..]).unwrap() }; 

    let our_cert_data = include_bytes!("test_data/our_cert.der");
    let our_cert = X509 { value: x509::X509::from_der(&our_cert_data[..]).unwrap() };

    let our_pkey_data = include_bytes!("test_data/our_private.pem");
    let our_pkey = PKey { value: pkey::PKey::private_key_from_pem(&our_pkey_data[..]).unwrap() }; 

    // TODO take this binary below and decrypt / verify it using the certs above

    /*
2017-08-07 19:37:06.000 - DEBUG - hex - 00000000:  4f 50 4e 46 71 06 00 00 00 00 00 00 38 00 00 00 68 74 74 70 3a 2f 2f 6f 70 63 66 6f 75 6e 64 61 OPNFq.......8...http://opcfounda
2017-08-07 19:37:06.000 - DEBUG - hex - 00000020:  74 69 6f 6e 2e 6f 72 67 2f 55 41 2f 53 65 63 75 72 69 74 79 50 6f 6c 69 63 79 23 42 61 73 69 63 tion.org/UA/SecurityPolicy#Basic
2017-08-07 19:37:06.000 - DEBUG - hex - 00000040:  31 32 38 52 73 61 31 35 0d 04 00 00 30 82 04 09 30 82 02 f1 a0 03 02 01 02 02 04 58 7f fc e6 30 128Rsa15....0...0..........X...0
2017-08-07 19:37:06.000 - DEBUG - hex - 00000060:  0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 24 31 0a 30 08 06 03 55 04 0a 0c 01 78 31 16 30 14 ...*.H........0$1.0...U....x1.0.
2017-08-07 19:37:06.000 - DEBUG - hex - 00000080:  06 03 55 04 03 0c 0d 55 61 45 78 70 65 72 74 40 43 41 4d 4f 30 1e 17 0d 31 37 30 31 31 38 32 33 ..U....UaExpert@CAMO0...17011823
2017-08-07 19:37:06.000 - DEBUG - hex - 000000a0:  34 30 32 32 5a 17 0d 32 32 30 31 31 37 32 33 34 30 32 32 5a 30 24 31 0a 30 08 06 03 55 04 0a 0c 4022Z..220117234022Z0$1.0...U...
2017-08-07 19:37:06.000 - DEBUG - hex - 000000c0:  01 78 31 16 30 14 06 03 55 04 03 0c 0d 55 61 45 78 70 65 72 74 40 43 41 4d 4f 30 82 01 22 30 0d .x1.0...U....UaExpert@CAMO0.."0.
2017-08-07 19:37:06.000 - DEBUG - hex - 000000e0:  06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 e0 30 35 7f c3 ..*.H.............0.........05..
2017-08-07 19:37:06.000 - DEBUG - hex - 00000100:  17 06 9b 25 48 8c 44 bb 5f 82 dd 6f 33 39 4e 5b e0 69 f8 4b 46 3a f4 46 3c 66 7c 1a 3c 48 87 24 ...%H.D._..o39N[.i.KF:.F<f|.<H.$
2017-08-07 19:37:06.000 - DEBUG - hex - 00000120:  6f 06 09 09 32 01 98 8f 5e 14 f9 f7 f8 d0 28 e9 e6 2f 34 55 3b 0c fd 73 93 25 96 6a d5 2a 32 f9 o...2...^.....(../4U;..s.%.j.*2.
2017-08-07 19:37:06.000 - DEBUG - hex - 00000140:  ba 2c 9a 43 58 f8 be 97 7d 53 19 5f a6 a7 82 47 dc 55 5d b0 63 f1 36 d6 1b 54 1e 6e 3c ed ba b6 .,.CX...}S._...G.U].c.6..T.n<...
2017-08-07 19:37:06.000 - DEBUG - hex - 00000160:  07 30 6f ff e8 3e 11 fc a4 2e 17 45 90 43 9e b3 62 57 54 7d 3d 02 56 51 90 8c 62 69 d1 a4 29 14 .0o..>.....E.C..bWT}=.VQ..bi..).
2017-08-07 19:37:06.000 - DEBUG - hex - 00000180:  62 d9 fd 8f 60 ee 06 39 53 02 ea 4d be c8 8e bf 24 2e 40 7b 19 e4 a4 f2 12 e6 e8 de 7f d5 41 92 b...`..9S..M....$.@{..........A.
2017-08-07 19:37:06.000 - DEBUG - hex - 000001a0:  de 1b 25 a1 ba 56 00 ea ff d8 1c 74 ce ab 2e fe 4a b3 65 e0 40 9f 89 f5 f3 62 48 96 50 85 a3 c7 ..%..V.....t....J.e.@....bH.P...
2017-08-07 19:37:06.000 - DEBUG - hex - 000001c0:  53 c2 32 a7 ec eb 2b 96 94 a5 8f 76 29 86 18 eb ab 56 02 b7 8a f9 3a 15 48 96 ab 91 b7 9c 9a c4 S.2...+....v)....V....:.H.......
2017-08-07 19:37:06.000 - DEBUG - hex - 000001e0:  58 4e 16 b4 0e c8 54 10 70 10 06 d5 a9 07 b9 f6 80 93 2b 87 50 52 99 73 8f d5 b1 02 03 01 00 01 XN....T.p.........+.PR.s........
2017-08-07 19:37:06.000 - DEBUG - hex - 00000200:  a3 82 01 41 30 82 01 3d 30 0c 06 03 55 1d 13 01 01 ff 04 02 30 00 30 50 06 09 60 86 48 01 86 f8 ...A0..=0...U.......0.0P..`.H...
2017-08-07 19:37:06.000 - DEBUG - hex - 00000220:  42 01 0d 04 43 16 41 22 47 65 6e 65 72 61 74 65 64 20 77 69 74 68 20 55 6e 69 66 69 65 64 20 41 B...C.A"Generated with Unified A
2017-08-07 19:37:06.001 - DEBUG - hex - 00000240:  75 74 6f 6d 61 74 69 6f 6e 20 55 41 20 42 61 73 65 20 4c 69 62 72 61 72 79 20 75 73 69 6e 67 20 utomation UA Base Library using
2017-08-07 19:37:06.001 - DEBUG - hex - 00000260:  4f 70 65 6e 53 53 4c 22 30 1d 06 03 55 1d 0e 04 16 04 14 21 af ba 22 1c 0e 77 0c 29 a1 00 60 cc OpenSSL"0...U......!.."..w.)..`.
2017-08-07 19:37:06.001 - DEBUG - hex - 00000280:  1b 0f 19 94 09 c2 1d 30 4f 06 03 55 1d 23 04 48 30 46 80 14 21 af ba 22 1c 0e 77 0c 29 a1 00 60 .......0O..U.#.H0F..!.."..w.)..`
2017-08-07 19:37:06.001 - DEBUG - hex - 000002a0:  cc 1b 0f 19 94 09 c2 1d a1 28 a4 26 30 24 31 0a 30 08 06 03 55 04 0a 0c 01 78 31 16 30 14 06 03 .........(.&0$1.0...U....x1.0...
2017-08-07 19:37:06.001 - DEBUG - hex - 000002c0:  55 04 03 0c 0d 55 61 45 78 70 65 72 74 40 43 41 4d 4f 82 04 58 7f fc e6 30 0e 06 03 55 1d 0f 01 U....UaExpert@CAMO..X...0...U...
2017-08-07 19:37:06.001 - DEBUG - hex - 000002e0:  01 ff 04 04 03 02 02 f4 30 20 06 03 55 1d 25 01 01 ff 04 16 30 14 06 08 2b 06 01 05 05 07 03 01 ........0 ..U.%.....0...+.......
2017-08-07 19:37:06.001 - DEBUG - hex - 00000300:  06 08 2b 06 01 05 05 07 03 02 30 39 06 03 55 1d 11 04 32 30 30 86 28 75 72 6e 3a 43 41 4d 4f 3a ..+.......09..U...200.(urn:CAMO:
2017-08-07 19:37:06.001 - DEBUG - hex - 00000320:  55 6e 69 66 69 65 64 41 75 74 6f 6d 61 74 69 6f 6e 3a 55 61 45 78 70 65 72 74 40 43 41 4d 4f 82 UnifiedAutomation:UaExpert@CAMO.
2017-08-07 19:37:06.001 - DEBUG - hex - 00000340:  04 43 41 4d 4f 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 82 01 01 00 bc e3 fc 85 56 39 1b .CAMO0...*.H.................V9.
2017-08-07 19:37:06.001 - DEBUG - hex - 00000360:  57 e4 ee 04 89 5a ba ce f8 1f 3f 3e 6c a8 19 d2 7c ae 39 9c cc ad c5 d1 77 d9 a8 e8 c7 44 7d 0f W....Z....?>l...|.9.....w....D}.
2017-08-07 19:37:06.001 - DEBUG - hex - 00000380:  61 60 72 cf 56 c7 9d f4 93 dc 9b be 50 22 53 8a 30 8d ae 22 62 3e 17 b8 ed f4 ef 97 b3 4f 74 4d a`r.V.......P"S.0.."b>.......OtM
2017-08-07 19:37:06.001 - DEBUG - hex - 000003a0:  d3 c5 7a d4 be 24 ae f9 9c c0 5c 5e a9 c2 ca 7b 3d 80 4b 9b 4d 41 fb d3 22 d0 f5 66 8f e9 27 d3 ..z..$....\^...{=.K.MA.."..f..'.
2017-08-07 19:37:06.001 - DEBUG - hex - 000003c0:  9b 93 89 3d 84 5b d9 96 11 5d 49 f1 1f a4 7d 0a cb 30 dc ae 16 11 98 ca ab 72 b0 eb a4 4a ac 2c ...=.[...]I...}..0.......r...J.,
2017-08-07 19:37:06.001 - DEBUG - hex - 000003e0:  88 e9 84 8c e1 f0 b1 6f 42 19 6e ca ef 25 81 99 c6 35 7e c5 43 e9 3e d8 64 22 13 3c 1c 8c 8b d1 .......oB.n..%...5~.C.>.d".<....
2017-08-07 19:37:06.001 - DEBUG - hex - 00000400:  02 18 4a c7 26 30 af a4 42 0c f3 56 4a 8b 72 c3 65 aa 6c 74 8a b9 72 5d d3 a4 3c 1e d3 ef b7 66 ..J.&0..B..VJ.r.e.lt..r]..<....f
2017-08-07 19:37:06.001 - DEBUG - hex - 00000420:  7d 40 3e 56 19 ec cd 21 2a 57 89 dc ba 9c 8e ae cb 48 c5 9d 26 96 63 33 87 1a 46 97 35 4f 87 b2 }@>V...!*W.......H..&.c3..F.5O..
2017-08-07 19:37:06.001 - DEBUG - hex - 00000440:  1a 7e 3a d2 44 a5 1b 03 ea 1f 68 26 7d e0 d4 ff 36 80 cb fe 47 1b cc 9d 0a 14 00 00 00 52 c7 31 .~:.D.....h&}...6...G........R.1
2017-08-07 19:37:06.001 - DEBUG - hex - 00000460:  3f 12 b9 58 d0 30 4c 80 e6 82 29 d7 e6 a4 de 3b 73 8b 07 28 f6 67 61 e9 16 9c b9 b3 49 3e cc aa ?..X.0L...)....;s..(.ga.....I>..
2017-08-07 19:37:06.001 - DEBUG - hex - 00000480:  09 5a 4c e3 f1 2f f0 7d cf fd 65 6b da 15 89 ea a1 ac a5 f2 11 6b 17 85 14 d1 5c 51 5e e3 d1 da .ZL../.}..ek.........k....\Q^...
2017-08-07 19:37:06.001 - DEBUG - hex - 000004a0:  99 fd 52 e4 48 63 87 f6 55 0d d2 44 28 68 64 5e ff 2a 96 23 d6 1b 48 19 b7 de 01 77 d5 34 54 5c ..R.Hc..U..D(hd^.*.#..H....w.4T\
2017-08-07 19:37:06.001 - DEBUG - hex - 000004c0:  da d9 f4 dc 88 1f bd e2 56 b4 e1 02 29 8d 4b ad 71 f4 26 0c 1b a1 20 b6 34 8a 69 f6 c2 6f 45 c7 ........V...).K.q.&... .4.i..oE.
2017-08-07 19:37:06.001 - DEBUG - hex - 000004e0:  eb 84 b4 36 86 e8 d5 ae 57 30 87 29 41 6d 57 e1 1f dc 91 2d 05 38 09 55 bb a0 de 5d b8 1d 05 2b ...6....W0.)AmW....-.8.U...]...+
2017-08-07 19:37:06.001 - DEBUG - hex - 00000500:  1f 36 34 d9 e4 67 8a 1e 20 53 6b ee b3 e9 f0 1f 8b 49 99 33 91 88 8b b4 fb 5e 02 ac 4b 58 fe 3f .64..g.. Sk......I.3.....^..KX.?
2017-08-07 19:37:06.001 - DEBUG - hex - 00000520:  ae 6e f9 57 ef eb 7a d6 64 75 bd 24 b5 90 12 da 8b fb 80 b5 3e c9 52 31 f6 8c df b9 c2 95 85 9d .n.W..z.du.$........>.R1........
2017-08-07 19:37:06.001 - DEBUG - hex - 00000540:  97 f3 9b a4 61 d7 1a 8a 3e 3f 07 72 e7 bf 14 d0 cd 21 7d d2 ea 0f 02 db e0 e9 69 56 96 40 f1 8a ....a...>?.r.....!}.......iV.@..
2017-08-07 19:37:06.001 - DEBUG - hex - 00000560:  16 3d 93 fd ec db d5 79 03 04 76 3d b2 83 51 89 77 1a 35 ac 67 a1 9f 8d fb e2 23 45 84 65 c2 f0 .=.....y..v=..Q.w.5.g.....#E.e..
2017-08-07 19:37:06.002 - DEBUG - hex - 00000580:  d5 5c 7e a4 00 e7 af aa c0 3d fb e5 d5 8d e2 e1 46 30 9b 56 32 65 78 f4 2e eb ef a2 03 b0 bf 2f .\~......=......F0.V2ex......../
2017-08-07 19:37:06.002 - DEBUG - hex - 000005a0:  11 0e 05 ad c9 72 f3 92 fb b2 67 0d 8f 5e 87 a8 e3 b8 68 b2 6b dc b3 26 35 f1 1e ac 24 3a bc b5 .....r....g..^....h.k..&5...$:..
2017-08-07 19:37:06.002 - DEBUG - hex - 000005c0:  7c 5d d2 f9 f2 67 bf d2 26 34 2c f8 c0 18 95 93 9b e2 af 57 a3 28 5b 74 00 c5 d7 b0 d6 45 c1 e5 |]...g..&4,........W.([t.....E..
2017-08-07 19:37:06.002 - DEBUG - hex - 000005e0:  4e ca 66 d9 95 28 43 85 04 94 32 7f de 5e 30 ac 45 fd 98 06 6f fa a5 2f 70 76 35 d9 ba e8 55 68 N.f..(C...2..^0.E...o../pv5...Uh
2017-08-07 19:37:06.002 - DEBUG - hex - 00000600:  06 2f 8b 7d b1 03 e3 c5 7b 55 b6 ac 46 b4 b8 39 05 5b 1f 2d 24 80 45 11 b2 f0 b2 cd ca a6 c0 de ./.}....{U..F..9.[.-$.E.........
2017-08-07 19:37:06.002 - DEBUG - hex - 00000620:  5e 51 cc 48 3b 70 8e 00 f5 5a d7 9b 5b cb b4 36 a1 9c 35 3a 34 9d 8a 02 2a 3a 92 5b e0 e1 e4 b7 ^Q.H;p...Z..[..6..5:4...*:.[....
2017-08-07 19:37:06.002 - DEBUG - hex - 00000640:  d0 cb 54 73 b3 33 4b a1 63 ba 9d e7 2b 1c 3e 1a 13 d3 85 4b 17 fe 29 91 90 4b 2b 4d 86 42 ca 0f ..Ts.3K.c...+.>....K..)..K+M.B..
2017-08-07 19:37:06.002 - DEBUG - hex - 00000660:  fd 11 e4 60 a5 31 8c d1 b0 45 a6 eb dc e2 5c bd 66                                              ...`.1...E....\.f
*/

}