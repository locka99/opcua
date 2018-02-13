//! This is a sample OPC UA Client that connects to the specified server, fetches some
//! values before exiting.
extern crate opcua_types;
extern crate opcua_core;
extern crate opcua_client;

use opcua_client::prelude::*;
use std::collections::HashSet;
use std::env;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

// This simple client will fetch values and exit, or if --subscribe is passed on the command line
// it will subscribe to values and run indefinitely, printing out changes to those values.

fn main() {
    // Optional - enable OPC UA logging
    opcua_core::init_logging();

    // Test for --subscribe
    let args: HashSet<String> = env::args().collect();
    let subscribe_flag = args.contains("--subscribe");

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

        // Important - the session you receive is reference counted because it is used by background
        // threads. You must only lock the session for as long as you need to use it and you should
        // release the lock (i.e. drop it) when your need to use it is over. The subscription thread
        // also needs access to the session to send and receive messages and won't
        // be able to if your lock is never released.

        {
            // Connect to the server
            let mut session = session.lock().unwrap();
            if let Err(result) = session.connect_and_activate_session() {
                println!("ERROR: Got an error while creating the default session - {:?}", result.description());
            }
        }

        // The --subscribe arg decides if code should subscribe to values, or just fetch those
        // values and exit
        let result = if subscribe_flag {
            subscribe(session)
        } else {
            read_values(session)
        };
        if let Err(result) = result {
            println!("ERROR: Got an error while performing action - {:?}", result.description());
        }
    } else {
        println!("ERROR: Sample client cannot create a session!");
    }
}

fn nodes_to_monitor() -> Vec<ReadValueId> {
    vec![
        ReadValueId::from(NodeId::from((2, "v1"))),
        ReadValueId::from(NodeId::from((2, "v2"))),
        ReadValueId::from(NodeId::from((2, "v3"))),
        ReadValueId::from(NodeId::from((2, "v4"))),
    ]
}

fn print_value(read_value_id: &ReadValueId, data_value: &DataValue) {
    let node_id = read_value_id.node_id.to_string();
    if let Some(ref value) = data_value.value {
        println!("Item \"{}\", Value = {:?}", node_id, value);
    } else {
        println!("Item \"{}\", Value not found, error: {}", node_id, data_value.status.as_ref().unwrap().description());
    }
}

fn subscribe(session: Arc<Mutex<Session>>) -> Result<(), StatusCode> {
    // Create a subscription
    println!("Creating subscription");

    // This scope is important - we don't want to session to be locked when the code hits the
    // loop below
    {
        let mut session = session.lock().unwrap();

        // Creates our subscription - one update every 5 seconds
        let subscription_id = session.create_subscription(5f64, 10, 30, 0, 0, true, DataChangeCallback::new(|items| {
            println!("Data change from server:");
            items.iter().for_each(|item| {
                print_value(&item.item_to_monitor(), &item.value());
            });
        }))?;
        println!("Created a subscription with id = {}", subscription_id);

        // Create some monitored items
        let read_nodes = nodes_to_monitor();
        let items_to_create: Vec<MonitoredItemCreateRequest> = read_nodes.into_iter().map(|read_node| {
            MonitoredItemCreateRequest::new(read_node, MonitoringMode::Reporting, MonitoringParameters::default())
        }).collect();
        let _ = session.create_monitored_items(subscription_id, items_to_create)?;
    }

    // Loops forever. The publish thread will call the callback with changes on the variables
    loop {
        {
            // Break the loop if connection goes down
            let session = session.lock().unwrap();
            if !session.is_connected() {
                println!("Connection to server broke, so terminating");
                break;
            }
        }

        // Main thread has nothing to do - just wait for publish events to roll in
        use std::thread;
        use std::time;
        thread::sleep(time::Duration::from_millis(1000));
    }

    Ok(())
}

fn read_values(session: Arc<Mutex<Session>>) -> Result<(), StatusCode> {
    // Fetch some values from the sample server
    let read_nodes = nodes_to_monitor();
    let data_values = {
        let mut session = session.lock().unwrap();
        session.read_nodes(read_nodes.clone())?.unwrap()
    };

    // Print the values out
    println!("Values from server:");
    read_nodes.iter().zip(data_values.iter()).for_each(|i| {
        print_value(i.0, i.1);
    });

    Ok(())
}

