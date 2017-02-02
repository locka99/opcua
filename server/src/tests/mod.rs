use std;
use std::path::{PathBuf};

use config::*;

fn make_test_file(filename: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(filename);
    path
}

#[test]
pub fn server_config_save() {
    let path = make_test_file("server_config.yaml");
    let config = ServerConfig::default_anonymous();
    assert!(config.save(&path).is_ok());
    if let Ok(config2) = ServerConfig::load(&path) {
        assert_eq!(config, config2);
    } else {
        panic!("Cannot load config from file");
    }
}
