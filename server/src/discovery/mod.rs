use std::collections::BTreeMap;

use opcua_client::client::Client;
use opcua_client::config::ClientConfig;

use config::ServerEndpoint;

/// Registers the specified endpoints with the specified discovery server
pub fn register_discover_server(discovery_server_url: &str, endpoints: &BTreeMap<String, ServerEndpoint>) {
    // Connect to a discovery server, and register the endpoints of this server with the
    // discovery server
    trace!("Discovery server registration stub is triggering for {}", discovery_server_url);
    let mut client = Client::new(ClientConfig::new("DiscoveryClient", "urn:DiscoveryClient"));
    /*    let result = client.register_server(discovery_server_url);
        if result.is_err() {
            error!("Cannot register server with discovery server {}", discovery_server_url);
        } */
}
