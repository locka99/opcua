use std;
use std::path::{PathBuf};

use opcua_core::types::*;

use config::*;

use address_space::*;

mod address_space;
mod services;

fn make_test_file(filename: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(filename);
    path
}

fn make_sample_address_space() -> AddressSpace {
    let mut address_space = AddressSpace::new();
    add_sample_vars_to_address_space(&mut address_space);
    address_space
}

fn add_sample_vars_to_address_space(address_space: &mut AddressSpace) {
    // Create a sample folder under objects folder
    let sample_folder_id = address_space.add_folder("Sample", "Sample", &AddressSpace::objects_folder_id()).unwrap();

    // Add some variables to our sample folder
    let vars = vec![
        Variable::new(&NodeId::new_string(1, "v1"), "v1", "v1", &DataTypeId::Int32, DataValue::new(Variant::Int32(30))),
        Variable::new(&NodeId::new_numeric(2, 300), "v2", "v2", &DataTypeId::Boolean, DataValue::new(Variant::Boolean(true))),
        Variable::new(&NodeId::new_string(1, "v3"), "v3", "v3", &DataTypeId::String, DataValue::new(Variant::String(UAString::from_str("Hello world"))))
    ];
    let _ = address_space.add_variables(&vars, &sample_folder_id);
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
