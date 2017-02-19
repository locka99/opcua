extern crate opcua_client;
extern crate opcua_core;

use opcua_client::prelude::*;

fn main() {
    let _ = opcua_core::init_logging();
    let mut client = Client::new("SampleClient", "urn:SampleClient");
    let session = client.new_session("opc.tcp://127.0.0.1:1234").unwrap();
    {
        let mut session = session.lock().unwrap();
        let result = session.connect();
        if result.is_err() {
            println!("Cannot connect to endpoint");
            return;
        }

        let endpoints = session.get_endpoints();

        // Fetch the values of v1, v2, v3
        session.browse(); //...

        // Print the values out
        println!("Values of nodes go here");

        session.disconnect();
    }
}
