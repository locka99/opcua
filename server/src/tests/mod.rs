use std;
use std::collections::VecDeque;
use std::path::PathBuf;

use chrono;
use time;

use opcua_types::*;
use opcua_types::node_ids::{ObjectId, ObjectTypeId, DataTypeId, ReferenceTypeId, VariableId};
use opcua_types::status_code::StatusCode::*;
use opcua_types::service_types::*;

use opcua_core::config::Config;
use opcua_core::crypto::*;
use opcua_core::comms::secure_channel::SecureChannel;

use address_space::address_space::*;
use address_space::variable::*;
use session::*;
use subscriptions::*;
use config::ServerConfig;

mod address_space;
mod services;
mod subscriptions;

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
        Variable::new(&NodeId::new(1, "v1"), "v1", "v1", "", 30i32),
        Variable::new(&NodeId::new(2, 300), "v2", "v2", "", true),
        Variable::new(&NodeId::new(1, "v3"), "v3", "v3", "", UAString::from("Hello world")),
        Variable::new(&NodeId::new(1, "v4"), "v4", "v4", "", 100.123f64),

    ];
    let _ = address_space.add_variables(vars, &sample_folder_id);
}

#[test]
pub fn server_config_sample_save() {
    // This test only exists to dump a sample config
    let config = ServerConfig::new_sample();
    let mut path = std::env::current_dir().unwrap();
    path.push("..");
    path.push("samples");
    path.push("server.conf");
    println!("Path is {:?}", path);
    assert!(config.save(&path).is_ok());
}

#[test]
pub fn server_config_save() {
    let path = make_test_file("server_config.yaml");
    let config = ServerConfig::new_anonymous("foo");
    assert!(config.save(&path).is_ok());
    if let Ok(config2) = ServerConfig::load(&path) {
        assert_eq!(config, config2);
    } else {
        panic!("Cannot load config from file");
    }
}

#[test]
pub fn server_config_invalid() {
    // Remove the endpoint
    let mut config = ServerConfig::new_anonymous("foo");
    assert!(config.is_valid());
    config.endpoints.clear();
    assert_eq!(config.is_valid(), false);

    // Insert a nonexistent user
    config = ServerConfig::new_anonymous("foo");
    config.endpoints.get_mut("none").unwrap().user_token_ids.insert("hello".to_string());
    assert_eq!(config.is_valid(), false);
}

#[test]
pub fn expired_publish_requests() {
    let now = chrono::Utc::now();
    let now_plus_5s = now + time::Duration::seconds(5);

    // Create two publish requests timestamped now, one which expires in > 30s, one which expires
    // in > 20s
    let now = DateTime::from(now.clone());
    let mut pr1 = PublishRequestEntry {
        request_id: 1,
        request: PublishRequest {
            request_header: RequestHeader::new(&NodeId::null(), &now, 1000),
            subscription_acknowledgements: None,
        },
    };
    pr1.request.request_header.timeout_hint = 5001;

    let mut pr2 = PublishRequestEntry {
        request_id: 2,
        request: PublishRequest {
            request_header: RequestHeader::new(&NodeId::null(), &now, 2000),
            subscription_acknowledgements: None,
        },
    };
    pr2.request.request_header.timeout_hint = 3000;

    // Create session with publish requests
    let secure_channel: SecureChannel = (SecurityPolicy::None, MessageSecurityMode::None).into();
    let mut session = Session::new_no_certificate_store(secure_channel);
    session.subscriptions.publish_request_queue = {
        let mut publish_request_queue = VecDeque::with_capacity(2);
        publish_request_queue.push_back(pr1);
        publish_request_queue.push_back(pr2);
        publish_request_queue
    };

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
        assert_eq!(response_header.response_header.service_result, BadTimeout);
    } else {
        panic!("Expected service faults for timed out publish requests")
    }
}