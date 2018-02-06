//! This is a sample OPC UA Client that connects to the specified server, fetches some
//! values before exiting.
extern crate opcua_types;
extern crate opcua_core;
extern crate opcua_client;

use opcua_client::prelude::*;
use std::path::PathBuf;
use std::str::FromStr;

fn main() {
    // Optional - enable OPC UA logging
    opcua_core::init_logging();

    // Use the sample client config to set up a client. The sample config has a number of named
    // endpoints one of which is marked as the default.
    let mut client = Client::new(ClientConfig::load(&PathBuf::from("../client.conf")).unwrap());

    // Ask the server associated with the default endpoint for its list of endpoints
    let endpoints = client.get_server_endpoints();
    if endpoints.is_err() {
        println!("ERROR: Can't get endpoints for server, error - {:?}", endpoints.unwrap_err().description());
        return;
    }
    let endpoints = endpoints.unwrap();
    println!("Server has these endpoints:");
    for e in &endpoints {
        println!("  {} - {:?} / {:?}", e.endpoint_url, SecurityPolicy::from_str(e.security_policy_uri.as_ref()).unwrap(), e.security_mode);
    }

    // Create a session to the default endpoint. It has to match one received from the get_endpoints call
    if let Ok(session) = client.new_session(&endpoints) {
        let mut session = session.lock().unwrap();
        // Connect and do something with the server
        let result = connect(&mut session);
        if result.is_err() {
            println!("ERROR: Got an error while creating the default session - {:?}", result.unwrap_err().description());
        }
    } else {
        println!("ERROR: Sample client cannot create a session!");
    }
}

fn subscribe(session: &mut Session) -> Result<(), StatusCode> {
    // Connect & activate the session.
    let _ = session.connect_and_activate_session()?;

    // Create a subscription
    let subscription_id = session.create_subscription(1f64, 10, 30, 0, 0, true)?;
    // TODO set callback for subscription

    let items_to_create = vec![
        MonitoredItemCreateRequest::new(ReadValueId::read_value(NodeId::new_string(2, "v1")), MonitoringMode::Reporting, MonitoringParameters {
            client_handle: 0,
            sampling_interval: 0f64,
            filter: ExtensionObject::null(),
            queue_size: 1,
            discard_oldest: true,
        }),
    ];

    let _ = session.create_monitored_items(subscription_id, items_to_create)?;

    loop {
        // Main thread has nothing to do - just wait for publish events to roll in
        use std::thread;
        thread::sleep_ms(1000)
    }
}

fn connect(session: &mut Session) -> Result<(), StatusCode> {
    // Connect & activate the session.
    let _ = session.connect_and_activate_session()?;

    // Fetch some values from the sample server
    let read_nodes = vec![
        ReadValueId::read_value(NodeId::new_string(2, "v1")),
        ReadValueId::read_value(NodeId::new_string(2, "v2")),
        ReadValueId::read_value(NodeId::new_string(2, "v3")),
        ReadValueId::read_value(NodeId::new_string(2, "v4")),
    ];
    let data_values = session.read_nodes(&read_nodes)?.unwrap();

    // Print the values out
    println!("Values from server:");
    for data_value in data_values.iter() {
        if let Some(ref value) = data_value.value {
            println!("Value = {:?}", value);
        } else {
            println!("Value not found, error: {}", data_value.status.as_ref().unwrap().description());
        }
    }

    Ok(())
}

