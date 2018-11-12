//! This is a sample that calls find servers on a OPC UA discovery server
extern crate clap;
extern crate opcua_client;

extern crate opcua_types;
extern crate opcua_console_logging;

use std::str::FromStr;

use opcua_client::prelude::*;
use opcua_types::url::is_opc_ua_binary_url;

fn main() {
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
    // Optional - enable OPC UA logging
    opcua_console_logging::init();

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
                    if is_opc_ua_binary_url(discovery_url.as_ref()) {
                        // Try to talk with it and get some endpoints
                        let client_config = ClientConfig::new("discovery-client", "urn:discovery-client");
                        let client = Client::new(client_config);

                        // Ask the server associated with the default endpoint for its list of endpoints
                        match client.get_server_endpoints_from_url(discovery_url.as_ref()) {
                            Result::Err(status_code) => {
                                println!("    ERROR: Can't get endpoints for this server url, error - {}", status_code);
                                continue;
                            }
                            Result::Ok(endpoints) => {
                                println!("    Server has these endpoints:");
                                for e in &endpoints {
                                    println!("      {} - {:?} / {:?}", e.endpoint_url, SecurityPolicy::from_str(e.security_policy_uri.as_ref()).unwrap(), e.security_mode);
                                }
                            }
                        }
                    }
                }
            } else {
                println!("  No discovery urls for this server");
            }
        }
    } else {
        println!("ERROR: Cannot find servers on discovery server - check this error - {:?}", servers.unwrap_err());
    }
}

