use std;
use std::path::PathBuf;

use chrono;
use time;

use prelude::*;
use session::*;

mod address_space;
mod services;
mod subscription;
mod monitored_item;

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
        Variable::new(&NodeId::new_string(1, "v1"), "v1", "v1", "", DataTypeId::Int32, DataValue::new(Variant::Int32(30))),
        Variable::new(&NodeId::new_numeric(2, 300), "v2", "v2", "", DataTypeId::Boolean, DataValue::new(Variant::Boolean(true))),
        Variable::new(&NodeId::new_string(1, "v3"), "v3", "v3", "", DataTypeId::String, DataValue::new(Variant::String(UAString::from_str("Hello world"))))
    ];
    let _ = address_space.add_variables(vars, &sample_folder_id);
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

#[test]
pub fn server_config_invalid() {
    let mut config = ServerConfig::default_anonymous();
    assert!(config.is_valid());
    config.endpoints.clear();
    assert_eq!(config.is_valid(), false);
    config = ServerConfig::default_anonymous();
    config.endpoints[0].anonymous = None;
    assert_eq!(config.is_valid(), false);
    config = ServerConfig::default_anonymous();
    config.endpoints[0].user = Some("hello".to_string());
    assert_eq!(config.is_valid(), false);
    config = ServerConfig::default_anonymous();
    config.endpoints[0].pass = Some("hello".to_string());
    assert_eq!(config.is_valid(), false);
}

#[test]
pub fn expired_publish_requests() {
    let now = chrono::UTC::now();
    let now_plus_5s = now + time::Duration::seconds(5);

    // Create two publish requests timestamped now, one which expires in > 30s, one which expires
    // in > 20s
    let now = DateTime::from_chrono(&now);
    let mut pr1 = PublishRequestEntry {
        request_id: 1,
        request: PublishRequest {
            request_header: RequestHeader::new(&NodeId::null(), &now, 1000),
            subscription_acknowledgements: None,
        }
    };
    pr1.request.request_header.timeout_hint = 5001;

    let mut pr2 = PublishRequestEntry {
        request_id: 2,
        request: PublishRequest {
            request_header: RequestHeader::new(&NodeId::null(), &now, 2000),
            subscription_acknowledgements: None,
        }
    };
    pr2.request.request_header.timeout_hint = 3000;

    // Create session with publish requests
    let mut session = Session::new();
    session.subscriptions.publish_request_queue = vec![pr1, pr2];

    // Expire requests, see which expire
    session.expire_stale_publish_requests(&now_plus_5s);
    let expired_responses = &session.subscriptions.publish_response_queue;

    // The > 30s timeout hint request should be expired and the other should remain
    assert_eq!(expired_responses.len(), 1);
    assert_eq!(session.subscriptions.publish_request_queue.len(), 1);
    assert_eq!(session.subscriptions.publish_request_queue[0].request.request_header.request_handle, 1000);

    let r1 = &expired_responses[0];
    if let SupportedMessage::ServiceFault(ref response_header) = r1.response {
        assert_eq!(response_header.response_header.request_handle, 2000);
        assert_eq!(response_header.response_header.service_result, BAD_TIMEOUT);
    } else {
        panic!("Expected service faults for timed out publish requests")
    }
}