use std::io::*;

use crate::crypto::SecurityPolicy;
use crate::types::*;

use crate::core::comms::{secure_channel::*, tcp_types::*};

fn hello_data() -> Vec<u8> {
    vec![
        0x48, 0x45, 0x4c, 0x46, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
        0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x00,
        0x00, 0x00, 0x6f, 0x70, 0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x31, 0x32, 0x37,
        0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x3a, 0x31, 0x32, 0x33, 0x34, 0x2f,
    ]
}

fn ack_data() -> Vec<u8> {
    vec![
        0x41, 0x43, 0x4b, 0x46, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0xff, 0x00, 0x00,
    ]
}

#[test]
pub fn hello() {
    let mut stream = Cursor::new(hello_data());
    let decoding_options = DecodingOptions::test();
    let hello = HelloMessage::decode(&mut stream, &decoding_options).unwrap();
    println!("hello = {:?}", hello);
    assert_eq!(hello.message_header.message_type, MessageType::Hello);
    assert_eq!(hello.message_header.message_size, 57);
    assert_eq!(hello.protocol_version, 0);
    assert_eq!(hello.receive_buffer_size, 655360);
    assert_eq!(hello.send_buffer_size, 655360);
    assert_eq!(hello.max_message_size, 0);
    assert_eq!(hello.max_chunk_count, 0);
    assert_eq!(
        hello.endpoint_url,
        UAString::from("opc.tcp://127.0.0.1:1234/")
    );
}

#[test]
pub fn acknowledge() {
    let mut stream = Cursor::new(ack_data());
    let decoding_options = DecodingOptions::test();
    let ack = AcknowledgeMessage::decode(&mut stream, &decoding_options).unwrap();
    println!("ack = {:?}", ack);
    assert_eq!(ack.message_header.message_type, MessageType::Acknowledge);
    assert_eq!(ack.message_header.message_size, 28);
    assert_eq!(ack.protocol_version, 0);
    assert_eq!(ack.receive_buffer_size, 524288);
    assert_eq!(ack.send_buffer_size, 524288);
    assert_eq!(ack.max_message_size, 16777216);
    assert_eq!(ack.max_chunk_count, 65535);
}

#[test]
pub fn secure_channel_nonce_basic128rsa15() {
    let mut sc = SecureChannel::new_no_certificate_store();
    sc.set_security_mode(MessageSecurityMode::SignAndEncrypt);
    sc.set_security_policy(SecurityPolicy::Basic128Rsa15);
    // Nonce which is not 32 bytes long is an error
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::null())
        .is_err());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b""))
        .is_err());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b"1"))
        .is_err());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b"012345678901234"))
        .is_err());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b"01234567890123456"))
        .is_err());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(
            b"01234567890123456789012345678901".as_ref()
        ))
        .is_err());
    // Nonce which is 16 bytes long is good
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b"0123456789012345"))
        .is_ok());
}

#[test]
pub fn secure_channel_nonce_basic256() {
    let mut sc = SecureChannel::new_no_certificate_store();
    sc.set_security_mode(MessageSecurityMode::SignAndEncrypt);
    sc.set_security_policy(SecurityPolicy::Basic256);
    // Nonce which is not 32 bytes long is an error
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::null())
        .is_err());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b""))
        .is_err());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b"1"))
        .is_err());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b"0123456789012345678901234567890"))
        .is_err());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(
            b"012345678901234567890123456789012".as_ref()
        ))
        .is_err());
    // Nonce which is 32 bytes long is good
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b"01234567890123456789012345678901"))
        .is_ok());
}

#[test]
pub fn secure_channel_nonce_none() {
    // When the security policy is none, you can set the nonce, but it doesn't care what length it is
    let mut sc = SecureChannel::new_no_certificate_store();
    sc.set_security_mode(MessageSecurityMode::None);
    sc.set_security_policy(SecurityPolicy::None);
    // Nonce which is 32 bytes long is good
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b"01234567890123456789012345678901"))
        .is_ok());
    // Nonce which is not 32 bytes long is good
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b"012"))
        .is_ok());
    assert!(sc
        .set_remote_nonce_from_byte_string(&ByteString::from(b""))
        .is_ok());
}
