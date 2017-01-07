use std;
use std::path::{PathBuf};

use config::*;
use handshake::*;

fn make_test_file(filename: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(filename);
    path
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
pub fn test_valid_message() {
    let mut message = MessageHeader {
        message_type: [b'A', b'B', b'C'],
        reserved: b'F',
        message_size: 0,
    };
    assert_eq!(message.is_acknowledge(), false);
    assert_eq!(message.is_hello(), false);
    assert_eq!(message.is_error(), false);

    message.message_type = [b'A', b'C', b'K'];
    assert_eq!(message.is_acknowledge(), true);
    message.reserved = b'X';
    assert_eq!(message.is_acknowledge(), false);
    message.reserved = b'F';

    message.message_type = [b'H', b'E', b'L'];
    assert_eq!(message.is_hello(), true);
    message.reserved = b'X';
    assert_eq!(message.is_hello(), false);
    message.reserved = b'F';

    message.message_type = [b'E', b'R', b'R'];
    assert_eq!(message.is_error(), true);
    message.reserved = b'X';
    assert_eq!(message.is_error(), false);
    message.reserved = b'F';
}
