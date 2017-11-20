//! This is a sample OPC UA Client that connects to the specified server, fetches some
//! values before exiting.
extern crate opcua_types;
extern crate opcua_core;
extern crate opcua_client;

use opcua_client::prelude::*;

fn main() {
    // Optional - enable OPC UA logging
    opcua_core::init_logging();

    let discovery_endpoint_url = "opc.tcp://localhost:4840/";

    // To find servers, we connect to a local discovery server and call FindServers.
    // The client API has a simple `find_servers` function that does it for us.
    let mut client = Client::new(ClientConfig::new("DiscoveryClient", "urn:DiscoveryClient"));
    let servers = client.find_servers(discovery_endpoint_url);
    if let Ok(servers) = servers {
        println!("Discovery server responded with {} servers:", servers.len());
        for server in &servers {
            // Each server is an `ApplicationDescription`
            println!("Server : {}", server.application_name);
            if let Some(ref discovery_urls) = server.discovery_urls {
                for discovery_url in discovery_urls {
                    println!("  {}", discovery_url);
                }
            } else {
                println!("  No discovery urls for this server");
            }
        }
    } else {
        println!("Cannot find servers on discovery server - check this error - {:?}", servers.unwrap_err());
    }
}

