use std;
use std::path::PathBuf;

use opcua_core::config::Config;
use opcua_core;
use opcua_types::MessageSecurityMode;
use opcua_core::crypto::SecurityPolicy;

use config::{ClientConfig, ClientEndpoint, ClientUserToken, ANONYMOUS_USER_TOKEN_ID};

fn make_test_file(filename: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(filename);
    path
}

pub fn default_sample_config() -> ClientConfig {
    use std::path::PathBuf;
    use opcua_core::crypto::SecurityPolicy;
    use opcua_types::MessageSecurityMode;

    let pki_dir = PathBuf::from("./pki");
    let endpoints = vec![
        ClientEndpoint {
            id: String::from("sample_none"),
            url: String::from("opc.tcp://127.0.0.1:4855"),
            security_policy: String::from(SecurityPolicy::None.to_uri()),
            security_mode: String::from(MessageSecurityMode::None),
            user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
        },
        ClientEndpoint {
            id: String::from("sample_basic128rsa15"),
            url: String::from("opc.tcp://127.0.0.1:4855"),
            security_policy: String::from(SecurityPolicy::Basic128Rsa15.to_uri()),
            security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
            user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
        },
        ClientEndpoint {
            id: String::from("sample_basic256"),
            url: String::from("opc.tcp://127.0.0.1:4855"),
            security_policy: String::from(SecurityPolicy::Basic256.to_uri()),
            security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
            user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
        },
        ClientEndpoint {
            id: String::from("sample_basic256sha256"),
            url: String::from("opc.tcp://127.0.0.1:4855"),
            security_policy: String::from(SecurityPolicy::Basic256Sha256.to_uri()),
            security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
            user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
        },
    ];
    let user_tokens = vec![
        ClientUserToken {
            id: String::from("sample_user"),
            user: String::from("sample"),
            password: String::from("sample1")
        }
    ];
    ClientConfig {
        application_name: "OPC UA Sample Client".to_string(),
        application_uri: "urn:SampleClient".to_string(),
        create_sample_keypair: true,
        trust_server_certs: true,
        product_uri: String::new(),
        pki_dir,
        default_endpoint: "sample_none".to_string(),
        endpoints,
        user_tokens
    }
}

#[test]
fn client_sample_config() {
    // This test exists to create the samples/client.conf file
    // This test only exists to dump a sample config
    let config = default_sample_config();
    let mut path = std::env::current_dir().unwrap();
    path.push("..");
    path.push("samples");
    path.push("client.conf");
    println!("Path is {:?}", path);
    assert!(config.save(&path).is_ok());
    assert!(config.is_valid());
}

#[test]
fn client_config() {
    let _ = opcua_core::init_logging();
    let path = make_test_file("client_config.yaml");
    println!("Client path = {:?}", path);
    let config = default_sample_config();
    assert!(config.save(&path).is_ok());
    if let Ok(config2) = ClientConfig::load(&path) {
        assert_eq!(config, config2);
    } else {
        panic!("Cannot load config from file");
    }
}

#[test]
fn client_invalid_security_policy_config() {
    let _ = opcua_core::init_logging();
    let mut config = default_sample_config();
    // Security policy is wrong
    config.endpoints = vec![
        ClientEndpoint {
            id: String::from("sample_none"),
            url: String::from("opc.tcp://127.0.0.1:4855"),
            security_policy: String::from("http://blah"),
            security_mode: String::from(MessageSecurityMode::None),
            user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
        }
    ];
    assert!(!config.is_valid());
}


#[test]
fn client_invalid_security_mode_config() {
    let _ = opcua_core::init_logging();
    let mut config = default_sample_config();
    // Message security mode is wrong
    config.endpoints = vec![
        ClientEndpoint {
            id: String::from("sample_none"),
            url: String::from("opc.tcp://127.0.0.1:4855"),
            security_policy: String::from(SecurityPolicy::Basic128Rsa15.to_uri()),
            security_mode: String::from("SingAndEncrypt"),
            user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
        }
    ];
    assert!(!config.is_valid());
}

#[test]
fn client_duplicate_endpoint_ids() {
    let _ = opcua_core::init_logging();
    let mut config = default_sample_config();
    // Two endpoints with the same id
    config.endpoints = vec![
        ClientEndpoint {
            id: String::from("sample_basic256"),
            url: String::from("opc.tcp://127.0.0.1:4855"),
            security_policy: String::from(SecurityPolicy::Basic256.to_uri()),
            security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
            user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
        },
        ClientEndpoint {
            id: String::from("sample_basic256"),
            url: String::from("opc.tcp://127.0.0.1:4855"),
            security_policy: String::from(SecurityPolicy::Basic256Sha256.to_uri()),
            security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
            user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
        },
    ];
    assert!(!config.is_valid());
}


#[test]
fn client_duplicate_user_tokens_config() {
    let _ = opcua_core::init_logging();
    let mut config = default_sample_config();
    // Duplicate user ids
    config.user_tokens = vec![
        ClientUserToken {
            id: String::from("x"),
            user: String::new(),
            password: String::new()
        },
        ClientUserToken {
            id: String::from("x"),
            user: String::new(),
            password: String::new()
        },
    ];
    assert!(!config.is_valid());
}

#[test]
fn client_anonymouse_user_tokens_id() {
    let _ = opcua_core::init_logging();
    let mut config = default_sample_config();
    // id anonymous is reserved
    config.user_tokens = vec![
        ClientUserToken {
            id: String::from("anonymous"),
            user: String::new(),
            password: String::new()
        },
    ];
    assert!(!config.is_valid());
}

