use std::io::{Cursor, Write};

use crate::{
    core::{
        comms::{chunker::*, message_chunk::*, secure_channel::*, tcp_types::MIN_CHUNK_SIZE},
        supported_message::SupportedMessage,
        tests::*,
    },
    crypto::{x509::X509, SecurityPolicy},
    from_hex,
    types::DecodingOptions,
};

fn sample_secure_channel_request_data_security_none() -> MessageChunk {
    let sample_data = vec![
        47, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 111, 112, 99, 102, 111, 117, 110, 100, 97,
        116, 105, 111, 110, 46, 111, 114, 103, 47, 85, 65, 47, 83, 101, 99, 117, 114, 105, 116,
        121, 80, 111, 108, 105, 99, 121, 35, 78, 111, 110, 101, 255, 255, 255, 255, 255, 255, 255,
        255, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 190, 1, 0, 0, 208, 130, 196, 162, 147, 106, 210, 1, 1,
        0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
        0, 0, 255, 255, 255, 255, 192, 39, 9, 0,
    ];

    let data = vec![0u8; 12 + sample_data.len()];
    let mut stream = Cursor::new(data);

    // Write a header and the sample request
    let _ = MessageChunkHeader {
        message_type: MessageChunkType::OpenSecureChannel,
        is_final: MessageIsFinalType::Final,
        message_size: 12 + sample_data.len() as u32,
        secure_channel_id: 1,
    }
    .encode(&mut stream);
    let _ = stream.write(&sample_data);

    // Decode chunk from stream
    stream.set_position(0);
    let decoding_options = DecodingOptions::test();
    let chunk = MessageChunk::decode(&mut stream, &decoding_options).unwrap();

    println!(
        "Sample chunk info = {:?}",
        chunk.message_header(&decoding_options).unwrap()
    );

    chunk
}

fn set_chunk_sequence_number(
    chunk: &mut MessageChunk,
    secure_channel: &SecureChannel,
    sequence_number: u32,
) -> u32 {
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

fn set_chunk_request_id(
    chunk: &mut MessageChunk,
    secure_channel: &SecureChannel,
    request_id: u32,
) -> u32 {
    // Read the sequence header
    let mut chunk_info = chunk.chunk_info(&secure_channel).unwrap();
    let old_request_id = chunk_info.sequence_header.request_id;
    chunk_info.sequence_header.request_id = request_id;
    // Write the sequence header out again with new value
    let mut stream = Cursor::new(&mut chunk.data[..]);
    stream.set_position(chunk_info.sequence_header_offset as u64);
    let _ = chunk_info.sequence_header.encode(&mut stream);
    old_request_id
}

fn make_large_read_response() -> SupportedMessage {
    let results = (0..10000).map(|i| DataValue::new_now(i as u32)).collect();
    ReadResponse {
        response_header: ResponseHeader::null(),
        results: Some(results),
        diagnostic_infos: None,
    }
    .into()
}

/// Encode a very large message with a maximum chunk size and ensure that it turns into multiple chunks
/// and that the chunks can be decoded back to the original message.
#[test]
fn chunk_multi_encode_decode() {
    let _ = Test::setup();

    let mut secure_channel = SecureChannel::new_no_certificate_store();
    secure_channel.set_decoding_options(DecodingOptions {
        client_offset: chrono::Duration::zero(),
        max_chunk_count: 0,
        max_string_length: 65535,
        max_byte_string_length: 65535,
        max_array_length: 20000, // Need to bump this up because large response uses a large array
        ..Default::default()
    });

    let response = make_large_read_response();

    // Create a very large message
    let sequence_number = 1000;
    let request_id = 100;
    let chunks = Chunker::encode(
        sequence_number,
        request_id,
        0,
        MIN_CHUNK_SIZE,
        &secure_channel,
        &response,
    )
    .unwrap();
    assert!(chunks.len() > 1);

    // Verify chunk byte len maxes out at == 8196
    let chunk_length = chunks[0].byte_len();
    trace!("MessageChunk length = {}", chunk_length);
    assert_eq!(chunk_length, MIN_CHUNK_SIZE);

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
    let chunks = Chunker::encode(
        sequence_number,
        request_id,
        0,
        MIN_CHUNK_SIZE,
        &secure_channel,
        &response,
    )
    .unwrap();
    assert!(chunks.len() > 1);

    let decoding_options = DecodingOptions::test();

    // All chunks except the last should be intermediate, the last should be final
    for (i, chunk) in chunks.iter().enumerate() {
        let message_header = chunk.message_header(&decoding_options).unwrap();
        if i == chunks.len() - 1 {
            assert_eq!(message_header.is_final, MessageIsFinalType::Final);
        } else {
            assert_eq!(message_header.is_final, MessageIsFinalType::Intermediate);
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
    let chunks = Chunker::encode(
        sequence_number,
        request_id,
        max_message_size,
        0,
        &secure_channel,
        &response,
    )
    .unwrap();
    assert_eq!(chunks.len(), 1);

    // Expect this to fail
    let err = Chunker::encode(
        sequence_number,
        request_id,
        max_message_size - 1,
        0,
        &secure_channel,
        &response,
    )
    .unwrap_err();
    assert_eq!(err, StatusCode::BadResponseTooLarge);
}

/// Encode a large message and then ensure verification throws error for secure channel id mismatch
#[test]
fn validate_chunks_secure_channel_id() {
    let _ = Test::setup();

    let mut secure_channel = SecureChannel::new_no_certificate_store();
    let response = make_large_read_response();

    // Create a very large message
    let sequence_number = 1000;
    let request_id = 100;
    let chunks = Chunker::encode(
        sequence_number,
        request_id,
        0,
        MIN_CHUNK_SIZE,
        &secure_channel,
        &response,
    )
    .unwrap();
    assert!(chunks.len() > 1);

    // Expect this to work
    let _ = Chunker::validate_chunks(sequence_number, &secure_channel, &chunks).unwrap();

    // Test secure channel id mismatch
    let old_secure_channel_id = secure_channel.secure_channel_id();
    secure_channel.set_secure_channel_id(old_secure_channel_id + 1);
    assert_eq!(
        Chunker::validate_chunks(sequence_number, &secure_channel, &chunks).unwrap_err(),
        StatusCode::BadSecureChannelIdInvalid
    );
}

/// Encode a large message and then ensure verification throws error for non-consecutive sequence numbers
#[test]
fn validate_chunks_sequence_number() {
    let _ = Test::setup();

    let secure_channel = SecureChannel::new_no_certificate_store();
    let response = make_large_read_response();

    // Create a very large message
    let sequence_number = 1000;
    let request_id = 100;
    let mut chunks = Chunker::encode(
        sequence_number,
        request_id,
        0,
        MIN_CHUNK_SIZE,
        &secure_channel,
        &response,
    )
    .unwrap();
    assert!(chunks.len() > 1);

    // Test sequence number cannot be < starting sequence number
    assert_eq!(
        Chunker::validate_chunks(sequence_number + 5000, &secure_channel, &chunks).unwrap_err(),
        StatusCode::BadSequenceNumberInvalid
    );

    // Test sequence number is returned properly
    let result = Chunker::validate_chunks(sequence_number, &secure_channel, &chunks).unwrap();
    assert_eq!(sequence_number + chunks.len() as u32 - 1, result);

    // Hack one of the chunks to alter its seq id
    let old_sequence_nr = set_chunk_sequence_number(&mut chunks[0], &secure_channel, 1001);
    assert_eq!(
        Chunker::validate_chunks(sequence_number, &secure_channel, &chunks).unwrap_err(),
        StatusCode::BadSecurityChecksFailed
    );

    // Hack the nth
    set_chunk_sequence_number(&mut chunks[0], &secure_channel, old_sequence_nr);
    let _ = set_chunk_sequence_number(&mut chunks[5], &secure_channel, 1008);
    assert_eq!(
        Chunker::validate_chunks(sequence_number, &secure_channel, &chunks).unwrap_err(),
        StatusCode::BadSecurityChecksFailed
    );
}

/// Encode a large message and ensure verification throws error for request id mismatches
#[test]
fn validate_chunks_request_id() {
    let _ = Test::setup();

    let secure_channel = SecureChannel::new_no_certificate_store();
    let response = make_large_read_response();

    // Create a very large message
    let sequence_number = 1000;
    let request_id = 100;
    let mut chunks = Chunker::encode(
        sequence_number,
        request_id,
        0,
        MIN_CHUNK_SIZE,
        &secure_channel,
        &response,
    )
    .unwrap();
    assert!(chunks.len() > 1);

    // Expect this to work
    let _ = Chunker::validate_chunks(sequence_number, &secure_channel, &chunks).unwrap();

    // Hack the request id so first chunk request id says 101 while the rest say 100
    let _ = set_chunk_request_id(&mut chunks[0], &secure_channel, 101);
    assert_eq!(
        Chunker::validate_chunks(sequence_number, &secure_channel, &chunks).unwrap_err(),
        StatusCode::BadSecurityChecksFailed
    );
}

/// Test creating a request, encoding it and decoding it.
#[test]
fn chunk_open_secure_channel() {
    let _ = Test::setup();

    let chunk = sample_secure_channel_request_data_security_none();
    let chunks = vec![chunk];

    let secure_channel = SecureChannel::new_no_certificate_store();

    trace!("Decoding original chunks");
    let request = Chunker::decode(&chunks, &secure_channel, None).unwrap();
    let request = match request {
        SupportedMessage::OpenSecureChannelRequest(request) => request,
        _ => {
            panic!("Not a OpenSecureChannelRequest");
        }
    };
    {
        let request_header = &request.request_header;
        assert_eq!(request_header.timestamp.ticks(), 131284521470690000);
        assert_eq!(request_header.request_handle, 1);
        assert!(request_header.return_diagnostics.is_empty());
        assert_eq!(request_header.audit_entry_id.is_null(), true);
        assert_eq!(request_header.timeout_hint, 0);
    }

    // Encode the message up again to chunks, decode and compare to original
    trace!("Encoding back to chunks");

    let chunks = Chunker::encode(
        1,
        1,
        0,
        0,
        &secure_channel,
        &SupportedMessage::OpenSecureChannelRequest(request.clone()),
    )
    .unwrap();
    assert_eq!(chunks.len(), 1);

    trace!("Decoding to compare the new version");
    let new_request = Chunker::decode(&chunks, &secure_channel, None).unwrap();
    let new_request = match new_request {
        SupportedMessage::OpenSecureChannelRequest(new_request) => new_request,
        _ => {
            panic!("Not a OpenSecureChannelRequest");
        }
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
        0x50, 0x38, 0x9b, 0xa9, 0x71, 0xd2, 0x01, 0xc0, 0x27, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff,
    ];

    let _ = Test::setup();

    let secure_channel = SecureChannel::new_no_certificate_store();
    let decoding_options = secure_channel.decoding_options();

    let mut stream = Cursor::new(chunk);
    let chunk = MessageChunk::decode(&mut stream, &decoding_options).unwrap();
    let chunks = vec![chunk];

    let decoded = Chunker::decode(&chunks, &secure_channel, None);
    if decoded.is_err() {
        panic!("Got error {:?}", decoded.unwrap_err());
    }
    let message = Chunker::decode(&chunks, &secure_channel, None).unwrap();
    //debug!("message = {:#?}", message);
    let response = match message {
        SupportedMessage::OpenSecureChannelResponse(response) => response,
        _ => {
            panic!("Not a OpenSecureChannelResponse");
        }
    };
    assert_eq!(response.response_header.request_handle, 0);
    assert_eq!(response.response_header.service_result, StatusCode::Good);
    assert_eq!(response.response_header.string_table.is_none(), true);
    assert_eq!(response.server_nonce, ByteString::null());
}

// Encode open secure channel back to itself and compare
#[test]
fn open_secure_channel() {
    let _ = Test::setup();
    let open_secure_channel_request = OpenSecureChannelRequest {
        request_header: RequestHeader {
            authentication_token: NodeId::new(0, 99),
            timestamp: DateTime::now(),
            request_handle: 1,
            return_diagnostics: DiagnosticBits::empty(),
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
    let new_open_secure_channel_request =
        serialize_test_and_return(open_secure_channel_request.clone());
    assert_eq!(open_secure_channel_request, new_open_secure_channel_request);

    // And the response
    let open_secure_channel_response = make_open_secure_channel_response();
    let new_open_secure_channel_response =
        serialize_test_and_return(open_secure_channel_response.clone());
    assert_eq!(
        open_secure_channel_response,
        new_open_secure_channel_response
    );
}

#[test]
fn security_policy_symmetric_encrypt_decrypt() {
    // Encrypt and decrypt directly to the security policy, make sure all is well
    let (secure_channel1, secure_channel2) = make_secure_channels(
        MessageSecurityMode::SignAndEncrypt,
        SecurityPolicy::Basic128Rsa15,
    );

    let src = vec![0u8; 100];
    let mut dst = vec![0u8; 200];

    let encrypted_len = secure_channel1
        .symmetric_sign_and_encrypt(&src, 0..80, 20..100, &mut dst)
        .unwrap();
    assert_eq!(encrypted_len, 100);

    let mut src2 = vec![0u8; 200];
    let decrypted_len = secure_channel2
        .symmetric_decrypt_and_verify(&dst, 0..80, 20..100, &mut src2)
        .unwrap();
    // End is at 100 - signature (20) - 1
    assert_eq!(decrypted_len, 79);

    // Compare the data, not the signature
    assert_eq!(&src[..80], &src2[..80]);
}

#[test]
fn asymmetric_decrypt_and_verify_sample_chunk() {
    let _ = Test::setup();

    let their_cert_data = include_bytes!("test_data/their_cert.der");
    let their_cert = X509::from_der(&their_cert_data[..]).unwrap();

    let their_key_data = include_bytes!("test_data/their_private.pem");
    let their_key = PrivateKey::from_pem(&their_key_data[..]).unwrap();

    let our_cert_data = include_bytes!("test_data/our_cert.der");
    let our_cert = X509::from_der(&our_cert_data[..]).unwrap();

    let our_key_data = include_bytes!("test_data/our_private.pem");
    let our_key = PrivateKey::from_pem(&our_key_data[..]).unwrap();

    // take this binary below and decrypt / verify it using the certs above
    let message_data = from_hex("4f504e46710600000000000038000000687474703a2f2f6f7063666f756e646174696f6e2e6f72672f55412f5365637572697479506f6c69637923426173696331323852736131350d04000030820409308202f1a0030201020204587ffce6300d06092a864886f70d01010b05003024310a3008060355040a0c01783116301406035504030c0d55614578706572744043414d4f301e170d3137303131383233343032325a170d3232303131373233343032325a3024310a3008060355040a0c01783116301406035504030c0d55614578706572744043414d4f30820122300d06092a864886f70d01010105000382010f003082010a0282010100e030357fc317069b25488c44bb5f82dd6f33394e5be069f84b463af4463c667c1a3c4887246f0609093201988f5e14f9f7f8d028e9e62f34553b0cfd739325966ad52a32f9ba2c9a4358f8be977d53195fa6a78247dc555db063f136d61b541e6e3cedbab607306fffe83e11fca42e174590439eb36257547d3d025651908c6269d1a4291462d9fd8f60ee06395302ea4dbec88ebf242e407b19e4a4f212e6e8de7fd54192de1b25a1ba5600eaffd81c74ceab2efe4ab365e0409f89f5f36248965085a3c753c232a7eceb2b9694a58f76298618ebab5602b78af93a154896ab91b79c9ac4584e16b40ec85410701006d5a907b9f680932b87505299738fd5b10203010001a38201413082013d300c0603551d130101ff04023000305006096086480186f842010d044316412247656e657261746564207769746820556e6966696564204175746f6d6174696f6e2055412042617365204c696272617279207573696e67204f70656e53534c22301d0603551d0e0416041421afba221c0e770c29a10060cc1b0f199409c21d304f0603551d2304483046801421afba221c0e770c29a10060cc1b0f199409c21da128a4263024310a3008060355040a0c01783116301406035504030c0d55614578706572744043414d4f8204587ffce6300e0603551d0f0101ff0404030202f430200603551d250101ff0416301406082b0601050507030106082b0601050507030230390603551d1104323030862875726e3a43414d4f3a556e69666965644175746f6d6174696f6e3a55614578706572744043414d4f820443414d4f300d06092a864886f70d01010b05000382010100bce3fc8556391b57e4ee04895abacef81f3f3e6ca819d27cae399cccadc5d177d9a8e8c7447d0f616072cf56c79df493dc9bbe5022538a308dae22623e17b8edf4ef97b34f744dd3c57ad4be24aef99cc05c5ea9c2ca7b3d804b9b4d41fbd322d0f5668fe927d39b93893d845bd996115d49f11fa47d0acb30dcae161198caab72b0eba44aac2c88e9848ce1f0b16f42196ecaef258199c6357ec543e93ed86422133c1c8c8bd102184ac72630afa4420cf3564a8b72c365aa6c748ab9725dd3a43c1ed3efb7667d403e5619eccd212a5789dcba9c8eaecb48c59d26966333871a4697354f87b21a7e3ad244a51b03ea1f68267de0d4ff3680cbfe471bcc9d0a1400000052c7313f12b958d0304c80e68229d7e6a4de3b738b0728f66761e9169cb9b3493eccaa095a4ce3f12ff07dcffd656bda1589eaa1aca5f2116b178514d15c515ee3d1da99fd52e4486387f6550dd2442868645eff2a9623d61b4819b7de0177d534545cdad9f4dc881fbde256b4e102298d4bad71f4260c1ba120b6348a69f6c26f45c7eb84b43686e8d5ae57308729416d57e11fdc912d05380955bba0de5db81d052b1f3634d9e4678a1e20536beeb3e9f01f8b49993391888bb4fb5e02ac4b58fe3fae6ef957efeb7ad66475bd24b59012da8bfb80b53ec95231f68cdfb9c295859d97f39ba461d71a8a3e3f0772e7bf14d0cd217dd2ea0f02dbe0e969569640f18a163d93fdecdbd5790304763db2835189771a35ac67a19f8dfbe223458465c2f0d55c7ea400e7afaac03dfbe5d58de2e146309b56326578f42eebefa203b0bf2f110e05adc972f392fbb2670d8f5e87a8e3b868b26bdcb32635f11eac243abcb57c5dd2f9f267bfd226342cf8c01895939be2af57a3285b7400c5d7b0d645c1e54eca66d9952843850494327fde5e30ac45fd98066ffaa52f707635d9bae85568062f8b7db103e3c57b55b6ac46b4b839055b1f2d24804511b2f0b2cdcaa6c0de5e51cc483b708e00f55ad79b5bcbb436a19c353a349d8a022a3a925be0e1e4b7d0cb5473b3334ba163ba9de72b1c3e1a13d3854b17fe2991904b2b4d8642ca0ffd11e460a5318cd1b045a6ebdce25cbd66");

    let mut secure_channel = SecureChannel::new_no_certificate_store();
    secure_channel.set_security_mode(MessageSecurityMode::SignAndEncrypt);
    secure_channel.set_security_policy(SecurityPolicy::Basic128Rsa15);

    // First we shall sign with our private key and encrypt with their public.
    secure_channel.set_cert(Some(our_cert));
    secure_channel.set_remote_cert(Some(their_cert));
    secure_channel.set_private_key(Some(our_key));

    let _ = secure_channel
        .verify_and_remove_security_forensic(&message_data, Some(their_key))
        .unwrap();
}

#[test]
fn test_x509_cross_thread() {
    use std::thread;
    let _ = Test::setup();
    let their_cert_data = include_bytes!("test_data/their_cert.der");
    let their_cert = X509::from_der(&their_cert_data[..]).unwrap();
    let child = thread::spawn(move || {
        println!("k={:?}", their_cert);
    });
    let _ = child.join();
}
