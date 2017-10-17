use opcua_core::config::Config;

use config::ClientConfig;
use std;
use std::path::PathBuf;

fn make_test_file(filename: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(filename);
    path
}

#[test]
fn client_config() {
    let path = make_test_file("client_config.yaml");
    println!("Client path = {:?}", path);
    let config = ClientConfig::new();
    assert!(config.save(&path).is_ok());
    if let Ok(config2) = ClientConfig::load(&path) {
        assert_eq!(config, config2);
    } else {
        panic!("Cannot load config from file");
    }
}