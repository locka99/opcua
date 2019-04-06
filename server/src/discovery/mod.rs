use opcua_client::prelude::{Client, ClientConfig, ClientBuilder};

use crate::state::ServerState;

/// Registers the specified endpoints with the specified discovery server
pub fn register_with_discovery_server(discovery_server_url: &str, server_state: &ServerState) {
    debug!("register_with_discovery_server, for {}", discovery_server_url);
    let server_config = trace_read_lock_unwrap!(server_state.config);

    // Create a client, ensuring to retry only once
    let mut client = ClientBuilder::new()
        .application_name("DiscoveryClient")
        .application_uri("urn:DiscoveryClient")
        .pki_dir(server_config.pki_dir.clone())
        .session_retry_limit(1)
        .client();

    if let Some(mut client) = client {
        // This follows the local discovery process described in part 12 of the spec, calling
        // find_servers on it first.

        // Connect to the server and call find_servers to ensure it is a discovery server
        match client.find_servers(discovery_server_url) {
            Ok(servers) => {
                debug!("Servers on the discovery endpoint - {:?}", servers);
                // Register the server
                let registered_server = server_state.registered_server();
                match client.register_server(discovery_server_url, registered_server) {
                    Ok(_) => {}
                    Err(err) => {
                        error!(r#"Cannot register server with discovery server \"{}\".
The errors immediately preceding this message may be caused by this issue.
Check if the error "{}" indicates the reason why that the registration could not happen.
The first thing you should ensure is that your server can connect to the discovery server and your
server's cert is trusted by the discovery server and vice versa."#, discovery_server_url, err);
                    }
                }
            }
            Err(err) => {
                error!("Cannot find servers on discovery url {}, error = {:?}", discovery_server_url, err);
            }
        }
    } else {
        error!("Cannot create a discovery server client config");
    }

    debug!("register_with_discovery_server, finished");
}
