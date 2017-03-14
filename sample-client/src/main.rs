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
    let session = client.new_session("opc.tcp://127.0.0.1:1234").unwrap();
    {
        let mut session = session.lock().unwrap();

        // Connect
        let result = session.connect();
        if result.is_err() {
            println!("Cannot connect to endpoint");
            return;
        }

        // Enumerate endpoints
        // TODO
        let endpoints = session.get_endpoints();

        // Fetch the values of v1, v2, v3
        // TODO
        session.browse(); //...

        // Print the values out
        // TODO
        println!("Values of nodes go here");

        // Disconnect
        session.disconnect();
    }
}
