//! This simple OPC UA client will do the following:
//!
//! 1. Read a configuration file (either default or the one specified using --config)
//! 2. Connect & create a session on one of those endpoints that match with its config (you can override which using --endpoint-id arg)
//! 3. Either:
//!    a) Read some values and exit
//!    b) Subscribe to values and loop forever printing out their values (using --subscribe)
extern crate clap;
extern crate opcua_client;


extern crate opcua_console_logging;

use std::sync::{Arc, RwLock};
use std::path::PathBuf;

use clap::{App, Arg};

use opcua_client::prelude::*;

fn main() {
    // Read command line arguments
    let (subscribe, config_file, endpoint_id) = {
        let m = App::new("Simple OPC UA Client")
            .arg(Arg::with_name("config")
                .long("config")
                .help("Sets the configuration file to read settings and endpoints from")
                .takes_value(true)
                .default_value("../client.conf")
                .required(false))
            .arg(Arg::with_name("id")
                .long("endpoint-id")
                .help("Sets the endpoint id from the config file to connect to")
                .takes_value(true)
                .default_value("")
                .required(false))
            .arg(Arg::with_name("subscribe")
                .long("subscribe")
                .help("Subscribes to values running indefinitely")
                .required(false))
            .get_matches();
        (m.is_present("subscribe"), m.value_of("config").unwrap().to_string(), m.value_of("id").unwrap().to_string())
    };

    // Optional - enable OPC UA logging
    opcua_console_logging::init();

    // Use the sample client config to set up a client. The sample config has a number of named
    // endpoints one of which is marked as the default.
    let mut client = Client::new(ClientConfig::load(&PathBuf::from(config_file)).unwrap());
    let endpoint_id: Option<&str> = if !endpoint_id.is_empty() { Some(&endpoint_id) } else { None };
    if let Ok(session) = client.connect_and_activate(endpoint_id) {
        // The --subscribe arg decides if code should subscribe to values, or just fetch those
        // values and exit
        let result = if subscribe {
            subscription_loop(session)
        } else {
            read_values(session)
        };
        if let Err(result) = result {
            println!("ERROR: Got an error while performing action - {:?}", result.description());
        }
    }
}

fn nodes_to_monitor() -> Vec<ReadValueId> {
    vec![
        ReadValueId::from(NodeId::new(2, "v1")),
        ReadValueId::from(NodeId::new(2, "v2")),
        ReadValueId::from(NodeId::new(2, "v3")),
        ReadValueId::from(NodeId::new(2, "v4")),
    ]
}

fn print_value(read_value_id: &ReadValueId, data_value: &DataValue) {
    let node_id = read_value_id.node_id.to_string();
    if let Some(ref value) = data_value.value {
        println!("Item \"{}\", Value = {:?}", node_id, value);
    } else {
        println!("Item \"{}\", Value not found, error: {}", node_id, data_value.status.as_ref().unwrap());
    }
}

fn subscription_loop(session: Arc<RwLock<Session>>) -> Result<(), StatusCode> {
    // Create a subscription
    println!("Creating subscription");

    // This scope is important - we don't want to session to be locked when the code hits the
    // loop below
    {
        let mut session = session.write().unwrap();

        // Creates our subscription
        let subscription_id = session.create_subscription(2000.0, 10, 30, 0, 0, true, |items| {
            println!("Data change from server:");
            items.iter().for_each(|item| {
                print_value(&item.item_to_monitor(), &item.value());
            });
        })?;
        println!("Created a subscription with id = {}", subscription_id);

        // Create some monitored items
        let read_nodes = nodes_to_monitor();
        let items_to_create: Vec<MonitoredItemCreateRequest> = read_nodes.into_iter().map(|read_node| {
            MonitoredItemCreateRequest::new(read_node, MonitoringMode::Reporting, MonitoringParameters::default())
        }).collect();
        let _ = session.create_monitored_items(subscription_id, &items_to_create)?;
    }

    // Loops forever. The publish thread will call the callback with changes on the variables
    loop {
        let mut session = session.write().unwrap();
        // Break the loop if connection goes down
        if !session.is_connected() {
            println!("Connection to server broke, so terminating");
            break;
        }
        // Main thread has nothing to do - just wait for publish events to roll in
        session.poll();
    }

    Ok(())
}

fn read_values(session: Arc<RwLock<Session>>) -> Result<(), StatusCode> {
    // Fetch some values from the sample server
    let read_nodes = nodes_to_monitor();
    let data_values = {
        let mut session = session.write().unwrap();
        session.read_nodes(&read_nodes)?.unwrap()
    };

    // Print the values out
    println!("Values from server:");
    read_nodes.iter().zip(data_values.iter()).for_each(|i| {
        print_value(i.0, i.1);
    });

    Ok(())
}

