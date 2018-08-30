use opcua_client::client::Client;
use opcua_client::config::ClientConfig;

use state::ServerState;

/// Registers the specified endpoints with the specified discovery server
pub fn register_with_discovery_server(discovery_server_url: &str, server_state: &ServerState) {
    debug!("register_with_discovery_server, for {}", discovery_server_url);
    let server_config = trace_read_lock_unwrap!(server_state.config);

    // Client's pki dir must match server's
    let mut config = ClientConfig::new("DiscoveryClient", "urn:DiscoveryClient");
    config.pki_dir = server_config.pki_dir.clone();
    let mut client = Client::new(config);

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
                    error!("Cannot register server with discovery server {}. Check for error {:?} to discover the reason why.", discovery_server_url, err);
                    error!("One solution you may try is to ensure your server's cert is trusted by the discovery server.");
                }
            }
        }
        Err(err) => {
            error!("Cannot find servers on discovery url {}, error = {:?}", discovery_server_url, err);
        }
    }

    debug!("register_with_discovery_server, finished");
}
