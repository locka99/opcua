use opcua_types::service_types::RegisteredServer;

use opcua_client::client::Client;
use opcua_client::config::ClientConfig;

use state::ServerState;

/// Registers the specified endpoints with the specified discovery server
pub fn register_discover_server(discovery_server_url: &str, server_state: &ServerState) {
    // This follows the local discovery process described in part 12 of the spec, calling
    // find_servers on it

    trace!("Discovery server registration stub is triggering for {}", discovery_server_url);
    let mut client = Client::new(ClientConfig::new("DiscoveryClient", "urn:DiscoveryClient"));

    let servers = client.find_servers(discovery_server_url);
    if let Ok(servers) = servers {
        debug!("Servers on the discovery endpoint - {:?}", servers);

        let registered_server: RegisteredServer = server_state.registered_server();
        let result = client.register_server(discovery_server_url, registered_server);
        if result.is_err() {
            error!("Cannot register server with discovery server {}", discovery_server_url);
        }
    } else {}
}
