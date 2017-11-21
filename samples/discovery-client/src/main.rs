//! This is a sample that calls find servers on a OPC UA discovery server
extern crate clap;

extern crate opcua_types;
extern crate opcua_core;
extern crate opcua_client;

use opcua_client::prelude::*;

fn main() {
    // Optional - enable OPC UA logging
    //opcua_core::init_logging();

    // Read the argument
    let url = {
        use clap::*;
        let matches = App::new("OPC UA Discovery client")
            .about(
                r#"Finds servers from a discovery url."#)
            .arg(Arg::with_name("url")
                .long("url")
                .help("The url for the discover server")
                .default_value("opc.tcp://localhost:4840/")
                .takes_value(true))
            .get_matches();
        matches.value_of("url").unwrap().to_string()
    };

    println!("Attempting to connect to discovery server {} ...", url);

    // The client API has a simple `find_servers` function that connects and returns servers for us.
    let mut client = Client::new(ClientConfig::new("DiscoveryClient", "urn:DiscoveryClient"));
    let servers = client.find_servers(url);
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
        println!("ERROR: Cannot find servers on discovery server - check this error - {:?}", servers.unwrap_err());
    }
}

