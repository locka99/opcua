use opcua_types::service_types::RegisteredServer;

use opcua_client::client::Client;
use opcua_client::config::ClientConfig;

use state::ServerState;

/// Registers the specified endpoints with the specified discovery server
pub fn register_discover_server(discovery_server_url: &str, server_state: &ServerState) {
    // Connect to a discovery server, and register the endpoints of this server with the
    // discovery server
    trace!("Discovery server registration stub is triggering for {}", discovery_server_url);
    let mut client = Client::new(ClientConfig::new("DiscoveryClient", "urn:DiscoveryClient"));
    let registered_server: RegisteredServer = server_state.registered_server();
    let result = client.register_server(discovery_server_url, registered_server);
    if result.is_err() {
        error!("Cannot register server with discovery server {}", discovery_server_url);
    }
}
