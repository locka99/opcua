//! These tests are specifically testing secure channel behaviour of signing, encrypting, decrypting and verifying
//! chunks containing messages
extern crate rustc_serialize as serialize;

use opcua_types::*;

use comms::chunker::*;
use comms::secure_channel::*;

use crypto::SecurityPolicy;

use tests::*;

fn test_encrypt_decrypt(message: SupportedMessage, security_mode: MessageSecurityMode, security_policy: SecurityPolicy) {
    let mut secure_channel = SecureChannel::new_no_certificate_store();
    secure_channel.security_mode = security_mode;
    secure_channel.security_policy = security_policy;

    secure_channel.local_nonce = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    secure_channel.remote_nonce = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    secure_channel.derive_keys();

    let mut chunks = Chunker::encode(1, 1, 0, 0, &secure_channel, &message).unwrap();
    assert_eq!(chunks.len(), 1);

    {
        let chunk = &mut chunks[0];

        let mut encrypted_data = vec![0u8; chunk.data.len() + 4096];
        let encrypted_size = secure_channel.apply_security(&chunk, &mut encrypted_data[..]).unwrap();
        trace!("Result of applying security = {}", encrypted_size);

        // We can't strip padding, so just compare up to original length
        let chunk2 = secure_channel.verify_and_remove_security(&encrypted_data[..encrypted_size]).unwrap();

        // Why offset 12? So we don't compare message_size part which may differ when padding is added. Less than ideal
        // TODO padding should be stripped from removed security and the message size should be same
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
    trace!("Result of applying security = {}", encrypted_size);

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
    error!("asymmetric_sign_and_encrypt_message_chunk_basic128rsa15");
    test_asymmetric_encrypt_decrypt(SupportedMessage::OpenSecureChannelResponse(make_open_secure_channel_response()), MessageSecurityMode::SignAndEncrypt, SecurityPolicy::Basic128Rsa15);
}

#[test]
fn asymmetric_sign_and_encrypt_message_chunk_basic256() {
    let _ = Test::setup();
    error!("asymmetric_sign_and_encrypt_message_chunk_basic256");
    test_asymmetric_encrypt_decrypt(SupportedMessage::OpenSecureChannelResponse(make_open_secure_channel_response()), MessageSecurityMode::SignAndEncrypt, SecurityPolicy::Basic256);
}

#[test]
fn asymmetric_sign_and_encrypt_message_chunk_basic256sha256() {
    let _ = Test::setup();
    error!("asymmetric_sign_and_encrypt_message_chunk_basic256sha256");
    test_asymmetric_encrypt_decrypt(SupportedMessage::OpenSecureChannelResponse(make_open_secure_channel_response()), MessageSecurityMode::SignAndEncrypt, SecurityPolicy::Basic256Sha256);
}

/// Create a message, encode it to a chunk, sign the chunk, verify the signature and decode back to message
#[test]
fn symmetric_sign_message_chunk_basic128rsa15() {
    let _ = Test::setup();
    error!("symmetric_sign_message_chunk_basic128rsa15");
    test_encrypt_decrypt(make_sample_message(), MessageSecurityMode::Sign, SecurityPolicy::Basic128Rsa15);
}

#[test]
fn symmetric_sign_message_chunk_basic256() {
    let _ = Test::setup();
    error!("symmetric_sign_message_chunk_basic256");
    test_encrypt_decrypt(make_sample_message(), MessageSecurityMode::Sign, SecurityPolicy::Basic256);
}

#[test]
fn symmetric_sign_message_chunk_basic256sha256() {
    let _ = Test::setup();
    error!("symmetric_sign_message_chunk_basic256sha256");
    test_encrypt_decrypt(make_sample_message(), MessageSecurityMode::Sign, SecurityPolicy::Basic256Sha256);
}

/// Create a message, encode it to a chunk, sign the chunk, encrypt, decrypt, verify the signature and decode back to message
#[test]
fn symmetric_sign_and_encrypt_message_chunk_basic128rsa15() {
    let _ = Test::setup();
    error!("symmetric_sign_and_encrypt_message_chunk_basic128rsa15");
    test_encrypt_decrypt(make_sample_message(), MessageSecurityMode::SignAndEncrypt, SecurityPolicy::Basic128Rsa15);
}

/// Create a message, encode it to a chunk, sign the chunk, encrypt, decrypt, verify the signature and decode back to message
#[test]
fn symmetric_sign_and_encrypt_message_chunk_basic256() {
    let _ = Test::setup();
    error!("symmetric_sign_and_encrypt_message_chunk_basic256");
    test_encrypt_decrypt(make_sample_message(), MessageSecurityMode::SignAndEncrypt, SecurityPolicy::Basic256);
}

/// Create a message, encode it to a chunk, sign the chunk, encrypt, decrypt, verify the signature and decode back to message
#[test]
fn symmetric_sign_and_encrypt_message_chunk_basic256sha256() {
    let _ = Test::setup();
    error!("symmetric_sign_and_encrypt_message_chunk_basic256sha256");
    test_encrypt_decrypt(make_sample_message(), MessageSecurityMode::SignAndEncrypt, SecurityPolicy::Basic256Sha256);
}
