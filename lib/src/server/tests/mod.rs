use std::{path::PathBuf, sync::Arc};

use chrono;
use time;

use crate::core::{config::Config, supported_message::SupportedMessage};
use crate::sync::*;
use crate::types::{status_code::StatusCode, *};

use crate::server::{
    address_space::{address_space::*, variable::*},
    builder::ServerBuilder,
    config::ServerConfig,
    session::*,
    subscriptions::*,
};

mod address_space;
mod events;
mod services;
mod subscriptions;

fn make_test_file(filename: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(filename);
    path
}

fn make_sample_address_space() -> Arc<RwLock<AddressSpace>> {
    let address_space = Arc::new(RwLock::new(AddressSpace::new()));
    add_sample_vars_to_address_space(address_space.clone());
    address_space
}

fn add_sample_vars_to_address_space(address_space: Arc<RwLock<AddressSpace>>) {
    let mut address_space = trace_write_lock!(address_space);

    let ns = address_space.register_namespace("urn:test").unwrap();

    // Create a sample folder under objects folder
    let sample_folder_id = address_space
        .add_folder("Sample", "Sample", &NodeId::objects_folder_id())
        .unwrap();

    // Add some variables to our sample folder
    let vars = vec![
        Variable::new(&NodeId::new(ns, "v1"), "v1", "v1", 30i32),
        Variable::new(&NodeId::new(ns, 300), "v2", "v2", true),
        Variable::new(
            &NodeId::new(ns, "v3"),
            "v3",
            "v3",
            UAString::from("Hello world"),
        ),
        Variable::new(&NodeId::new(ns, "v4"), "v4", "v4", 100.123f64),
    ];
    let _ = address_space.add_variables(vars, &sample_folder_id);
}

#[test]
pub fn server_config_sample_save() {
    // This test only exists to dump a sample config
    let config = ServerBuilder::new_sample().config();
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
    let config = ServerBuilder::new_anonymous("foo").config();
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
    let mut config = ServerBuilder::new_anonymous("foo").config();
    assert!(config.is_valid());
    config.endpoints.clear();
    assert_eq!(config.is_valid(), false);

    // Insert a nonexistent user
    config = ServerBuilder::new_anonymous("foo").config();
    config
        .endpoints
        .get_mut("none")
        .unwrap()
        .user_token_ids
        .insert("hello".to_string());
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
        results: None,
    };
    pr1.request.request_header.timeout_hint = 5001;

    let mut pr2 = PublishRequestEntry {
        request_id: 2,
        request: PublishRequest {
            request_header: RequestHeader::new(&NodeId::null(), &now, 2000),
            subscription_acknowledgements: None,
        },
        results: None,
    };
    pr2.request.request_header.timeout_hint = 3000;

    // Create session with publish requests
    let mut session = Session::new_no_certificate_store();

    {
        let publish_request_queue = session.subscriptions_mut().publish_request_queue();
        publish_request_queue.clear();
        publish_request_queue.push_back(pr1);
        publish_request_queue.push_back(pr2);
        publish_request_queue
    };

    // Expire requests, see which expire
    session.expire_stale_publish_requests(&now_plus_5s);

    // The > 30s timeout hint request should be expired and the other should remain

    // Remain
    {
        let publish_request_queue = session.subscriptions_mut().publish_request_queue();
        assert_eq!(publish_request_queue.len(), 1);
        assert_eq!(
            publish_request_queue[0]
                .request
                .request_header
                .request_handle,
            1000
        );
    }

    // Expire
    {
        let publish_response_queue = session.subscriptions_mut().publish_response_queue();
        assert_eq!(publish_response_queue.len(), 1);

        let r1 = &publish_response_queue[0];
        if let SupportedMessage::ServiceFault(ref response_header) = r1.response {
            assert_eq!(response_header.response_header.request_handle, 2000);
            assert_eq!(
                response_header.response_header.service_result,
                StatusCode::BadTimeout
            );
        } else {
            panic!("Expected service faults for timed out publish requests")
        }
    }
}
