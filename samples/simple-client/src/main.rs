//! This simple OPC UA client will do the following:
//!
//! 1. Read a configuration file (either default or the one specified using --config)
//! 2. Connect & create a session on one of those endpoints that match with its config (you can override which using --endpoint-id arg)
//! 3. Either:
//!    a) Read some values and exit
//!    b) Subscribe to values and loop forever printing out their values (using --subscribe)
use std::sync::{Arc, RwLock};

use clap::{App, Arg};

use opcua_client::prelude::*;

fn main() {
    // Read command line arguments
    let url = {
        let m = App::new("Simple OPC UA Client")
            .arg(Arg::with_name("url")
                .long("url")
                .help("Specify the OPC UA endpoint to connect to")
                .takes_value(true)
                .default_value("opc.tcp://localhost:4855")
                .required(false))
            .get_matches();
        m.value_of("url").unwrap().to_string()
    };

    // Optional - enable OPC UA logging
    opcua_console_logging::init();

    // Make the client configuration
    let mut client = ClientBuilder::new()
        .application_name("Simple Client")
        .application_uri("urn:SimpleClient")
        .trust_server_certs(true)
        .client().unwrap();

    if let Ok(session) = client.connect_to_endpoint((url.as_ref(), SecurityPolicy::None.to_str(), MessageSecurityMode::None, UserTokenPolicy::anonymous()), IdentityToken::Anonymous) {
        if let Err(result) = subscription_loop(session) {
            println!("ERROR: Got an error while performing action - {}", result);
        }
    }
}

fn subscription_loop(session: Arc<RwLock<Session>>) -> Result<(), StatusCode> {
    // This scope is important - we don't want the session to be locked when the code hits the
    // loop below
    {
        let mut session = session.write().unwrap();

        // Creates our subscription
        let subscription_id = session.create_subscription(2000.0, 10, 30, 0, 0, true, DataChangeCallback::new(|items| {
            println!("Data change from server:");
            items.iter().for_each(|item| {
                print_value(&item.item_to_monitor(), &item.value());
            });
        }))?;
        println!("Created a subscription with id = {}", subscription_id);

        // Create some monitored items
        let read_nodes = vec![
            ReadValueId::from(NodeId::new(2, "v1")),
            ReadValueId::from(NodeId::new(2, "v2")),
            ReadValueId::from(NodeId::new(2, "v3")),
            ReadValueId::from(NodeId::new(2, "v4")),
        ];
        let items_to_create: Vec<MonitoredItemCreateRequest> = read_nodes.into_iter().map(|read_node| {
            MonitoredItemCreateRequest::new(read_node, MonitoringMode::Reporting, MonitoringParameters::default())
        }).collect();
        let _ = session.create_monitored_items(subscription_id, TimestampsToReturn::Both, &items_to_create)?;
    }

    // Loops forever. The publish thread will call the callback with changes on the variables
    let _ = Session::run(session);

    Ok(())
}

fn print_value(read_value_id: &ReadValueId, data_value: &DataValue) {
    let node_id = read_value_id.node_id.to_string();
    if let Some(ref value) = data_value.value {
        println!("Item \"{}\", Value = {:?}", node_id, value);
    } else {
        println!("Item \"{}\", Value not found, error: {}", node_id, data_value.status.as_ref().unwrap());
    }
}