use std::io::*;

use opcua_types::*;

use comms::*;

fn hello_data() -> Vec<u8> {
    vec![
        0x48, 0x45, 0x4c, 0x46, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
        0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x00,
        0x00, 0x00, 0x6f, 0x70, 0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x31, 0x32, 0x37,
        0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x3a, 0x31, 0x32, 0x33, 0x34, 0x2f]
}

fn ack_data() -> Vec<u8> {
    vec![
        0x41, 0x43, 0x4b, 0x46, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0xff, 0x00, 0x00]
}

#[test]
pub fn hello() {
    let mut stream = Cursor::new(hello_data());
    let hello = HelloMessage::decode(&mut stream).unwrap();
    println!("hello = {:?}", hello);
    assert_eq!(hello.message_header.message_type, MessageType::Hello);
    assert_eq!(hello.message_header.message_size, 57);
    assert_eq!(hello.protocol_version, 0);
    assert_eq!(hello.receive_buffer_size, 655360);
    assert_eq!(hello.send_buffer_size, 655360);
    assert_eq!(hello.max_message_size, 0);
    assert_eq!(hello.max_chunk_count, 0);
    assert_eq!(hello.endpoint_url, UAString::from_str("opc.tcp://127.0.0.1:1234/"));
}

#[test]
pub fn acknowledge() {
    let mut stream = Cursor::new(ack_data());
    let ack = AcknowledgeMessage::decode(&mut stream).unwrap();
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
pub fn secure_channel_nonce() {
    let mut sc = SecureChannelToken::new();
    // Nonce which is not 32 bytes long is an error
    assert!(sc.set_their_nonce(&ByteString::null()).is_err());
    assert!(sc.set_their_nonce(&ByteString::from_bytes(b"")).is_err());
    assert!(sc.set_their_nonce(&ByteString::from_bytes(b"1")).is_err());
    assert!(sc.set_their_nonce(&ByteString::from_bytes(b"0123456789012345678901234567890")).is_err());
    assert!(sc.set_their_nonce(&ByteString::from_bytes(b"012345678901234567890123456789012")).is_err());
    // Nonce which is 32 bytes long is good
    assert!(sc.set_their_nonce(&ByteString::from_bytes(b"01234567890123456789012345678901")).is_ok());
}