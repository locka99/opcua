use std::{self, collections::BTreeMap, path::PathBuf};

use crate::core::config::Config;
use crate::crypto::SecurityPolicy;
use crate::types::*;

use crate::async_client::{
    builder::ClientBuilder,
    config::{ClientConfig, ClientEndpoint, ClientUserToken, ANONYMOUS_USER_TOKEN_ID},
};

fn make_test_file(filename: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(filename);
    path
}

pub fn sample_builder() -> ClientBuilder {
    ClientBuilder::new()
        .application_name("OPC UA Sample Client")
        .application_uri("urn:SampleClient")
        .create_sample_keypair(true)
        .certificate_path("own/cert.der")
        .private_key_path("private/private.pem")
        .trust_server_certs(true)
        .pki_dir("./pki")
        .endpoints(vec![
            (
                "sample_none",
                ClientEndpoint {
                    url: String::from("opc.tcp://127.0.0.1:4855/"),
                    security_policy: String::from(SecurityPolicy::None.to_str()),
                    security_mode: String::from(MessageSecurityMode::None),
                    user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
                },
            ),
            (
                "sample_basic128rsa15",
                ClientEndpoint {
                    url: String::from("opc.tcp://127.0.0.1:4855/"),
                    security_policy: String::from(SecurityPolicy::Basic128Rsa15.to_str()),
                    security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
                    user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
                },
            ),
            (
                "sample_basic256",
                ClientEndpoint {
                    url: String::from("opc.tcp://127.0.0.1:4855/"),
                    security_policy: String::from(SecurityPolicy::Basic256.to_str()),
                    security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
                    user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
                },
            ),
            (
                "sample_basic256sha256",
                ClientEndpoint {
                    url: String::from("opc.tcp://127.0.0.1:4855/"),
                    security_policy: String::from(SecurityPolicy::Basic256Sha256.to_str()),
                    security_mode: String::from(MessageSecurityMode::SignAndEncrypt),
                    user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
                },
            ),
        ])
        .default_endpoint("sample_none")
        .user_token(
            "sample_user",
            ClientUserToken::user_pass("sample1", "sample1pwd"),
        )
        .user_token(
            "sample_user2",
            ClientUserToken::user_pass("sample2", "sample2pwd"),
        )
}

pub fn default_sample_config() -> ClientConfig {
    sample_builder().config()
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

    let saved = config.save(&path);
    println!("Saved = {:?}", saved);
    assert!(saved.is_ok());
    assert!(config.is_valid());
}

#[test]
fn client_config() {
    let path = make_test_file("client_config.yaml");
    println!("Client path = {:?}", path);
    let config = default_sample_config();
    let saved = config.save(&path);
    println!("Saved = {:?}", saved);
    assert!(config.save(&path).is_ok());
    if let Ok(config2) = ClientConfig::load(&path) {
        assert_eq!(config, config2);
    } else {
        panic!("Cannot load config from file");
    }
}

#[test]
fn client_invalid_security_policy_config() {
    let mut config = default_sample_config();
    // Security policy is wrong
    config.endpoints = BTreeMap::new();
    config.endpoints.insert(
        String::from("sample_none"),
        ClientEndpoint {
            url: String::from("opc.tcp://127.0.0.1:4855"),
            security_policy: String::from("http://blah"),
            security_mode: String::from(MessageSecurityMode::None),
            user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
        },
    );
    assert!(!config.is_valid());
}

#[test]
fn client_invalid_security_mode_config() {
    let mut config = default_sample_config();
    // Message security mode is wrong
    config.endpoints = BTreeMap::new();
    config.endpoints.insert(
        String::from("sample_none"),
        ClientEndpoint {
            url: String::from("opc.tcp://127.0.0.1:4855"),
            security_policy: String::from(SecurityPolicy::Basic128Rsa15.to_uri()),
            security_mode: String::from("SingAndEncrypt"),
            user_token_id: ANONYMOUS_USER_TOKEN_ID.to_string(),
        },
    );
    assert!(!config.is_valid());
}

#[test]
fn client_anonymous_user_tokens_id() {
    let mut config = default_sample_config();
    // id anonymous is reserved
    config.user_tokens = BTreeMap::new();
    config.user_tokens.insert(
        String::from("ANONYMOUS"),
        ClientUserToken {
            user: String::new(),
            password: Some(String::new()),
            cert_path: None,
            private_key_path: None,
        },
    );
    assert!(!config.is_valid());
}
