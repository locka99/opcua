//! This is a sample OPC UA Client
//! It connects to the specified server, fetches some values before exiting.
extern crate opcua_client;
extern crate opcua_core;

use opcua_client::prelude::*;

fn main() {
    // Logging is optional
    let _ = opcua_core::init_logging();

    // Create the client's particulars
    let mut client = Client::new("SampleClient", "urn:SampleClient");

    // Create a session
    if let Ok(session) = client.new_session("opc.tcp://127.0.0.1:1234") {
        let mut session = session.lock().unwrap();

        // Connect
        let result = session.connect_and_activate_session();
        if result.is_err() {
            println!("Cannot connect to endpoint");
            return;
        }

        // Enumerate endpoints
        // TODO
        let endpoints = session.get_endpoints();

        // Fetch some values from the sample server
        let read_nodes = vec![
            ReadValueId::read_value(NodeId::new_string(1, "free_memory")),
            ReadValueId::read_value(NodeId::new_numeric(1, 1001)),
        ];
        let results = session.read_nodes(&read_nodes);

        // Print the values out
        if let Ok(results) = results {
            println!("Values of nodes {:?}", results);
        } else {
            println!("Got error reading results = {:?}", results.unwrap_err());
        }

        // Disconnect
        session.disconnect();
    } else {
        println!("Sample client cannot create a session!");
    }
}
