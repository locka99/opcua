use std;
use std::io::*;
use std::path::{PathBuf};

use opcua_core::types::*;

use config::*;
use comms::handshake::*;

fn make_test_file(filename: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(filename);
    path
}

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
pub fn test_server_config_save() {
    let path = make_test_file("server_config.yaml");
    let config = ServerConfig::default();
    assert!(config.save(&path).is_ok());
    if let Ok(config2) = ServerConfig::load(&path) {
        assert_eq!(config, config2);
    } else {
        panic!("Cannot load config from file");
    }
}

#[test]
pub fn test_hello() {
    let mut stream = Cursor::new(hello_data());
    let hello = HelloMessage::decode(&mut stream).unwrap();
    println!("hello = {:?}", hello);
    assert_eq!(hello.message_header.message_type, MessageType::Hello);
    assert_eq!(hello.message_header.message_size, 57);
    assert_eq!(hello.protocol_version, 0);
    assert_eq!(hello.receive_buffer_size, 655360);
    assert_eq!(hello.send_buffer_size, 655360);
    assert_eq!(hello.max_message_size, 0);
    assert_eq!(hello.max_chunk_count,0);
    assert_eq!(hello.endpoint_url, UAString::from_str("opc.tcp://127.0.0.1:1234/"));
}

#[test]
pub fn test_acknowledge() {
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
