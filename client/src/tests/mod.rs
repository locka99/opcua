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
fn client_sample_config() {
    // This test exists to create the samples/client.conf file
    // This test only exists to dump a sample config
    let config = ClientConfig::default_sample();
    let mut path = std::env::current_dir().unwrap();
    path.push("..");
    path.push("samples");
    path.push("client.conf");
    println!("Path is {:?}", path);
    assert!(config.save(&path).is_ok());
}

#[test]
fn client_config() {
    let path = make_test_file("client_config.yaml");
    println!("Client path = {:?}", path);
    let config = ClientConfig::default_sample();
    assert!(config.save(&path).is_ok());
    if let Ok(config2) = ClientConfig::load(&path) {
        assert_eq!(config, config2);
    } else {
        panic!("Cannot load config from file");
    }
}
