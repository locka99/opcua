extern crate opcua_client;

use opcua_client::prelude::*;

fn main() {
    let mut client = Client::new("SampleClient", "urn:SampleClient");
    let session = client.new_session("opc.tcp://127.0.0.1:1234");
    {
        let mut session = session.lock().unwrap();
        let result = session.connect();
        if result.is_err() {
            println!("Cannot connect to endpoint");
            return;
        }

        // Fetch the values of v1, v2, v3
        session.browse(); //...

        // Print the values out
        println!("Values of nodes go here");

        session.disconnect();
    }
}
