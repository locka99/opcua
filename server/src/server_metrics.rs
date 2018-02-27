//! The server metrics module maintains a snapshot of server state that can be used by anything that wants
//! to see what is happening in the server. State is updated by the server as sessions are added, removed,
//! and when subscriptions / monitored items are added, removed.

use config;
use opcua_types::DateTime;
use server;
use server_state;

#[derive(Serialize)]
pub struct ServerMetrics {
    pub server: Server,
    pub config: Option<config::ServerConfig>,
    pub connections: Vec<Connection>,
}

#[derive(Serialize)]
pub struct Server {
    pub start_time: String,
    pub uptime_ms: i64,
}

#[derive(Serialize)]
pub struct Connection {
    pub id: String,
    // creation time
    // state
    pub client_name: String,
    pub client_ip: String,
    pub subscriptions: Vec<Subscription>,
}

#[derive(Serialize)]
pub struct Subscription {
    id: u32,
    priority: u8,
    publishing_enabled: bool,
    publishing_interval: f64,
    monitored_items: Vec<MonitoredItem>,
}

#[derive(Serialize)]
pub struct MonitoredItem {}

impl ServerMetrics {
    pub fn new() -> ServerMetrics {
        // Sample metrics
        ServerMetrics {
            server: Server {
                start_time: String::new(),
                uptime_ms: 0,
            },
            config: None,
            connections: Vec::new(),
        }
    }

    pub fn set_server_info(&mut self, server: &server::Server) {
        let server_state = trace_read_lock_unwrap!(server.server_state);
        let server_config = trace_read_lock_unwrap!(server_state.config);

        // For security, blank out user tokens
        let mut config = server_config.clone();
        config.user_tokens.clear();
        config.user_tokens.insert(String::new(), config::ServerUserToken {
            user: String::from("User identity tokens have been removed"),
            pass: None,
        });
        self.config = Some(config.clone());
    }

    pub fn update_from_server_state(&mut self, server_state: &server_state::ServerState) {
        let start_time = &server_state.start_time;
        let now = DateTime::now();

        self.server.start_time = start_time.as_chrono().to_rfc3339();

        let elapsed = now.as_chrono().signed_duration_since(start_time.as_chrono());
        self.server.uptime_ms = elapsed.num_milliseconds();
    }

    pub fn update_from_connections(&mut self, connections: &server::Connections) {
        self.connections = connections.iter().map(|c| {
            let connection = trace_read_lock_unwrap!(c);

            let session = connection.session();
            let session = trace_read_lock_unwrap!(session);

            let subscriptions = session.subscriptions.subscriptions().iter().map(|subscription| {
                let subscription = subscription.1;
                Subscription {
                    id: subscription.subscription_id,
                    priority: subscription.priority,
                    publishing_enabled: subscription.publishing_enabled,
                    publishing_interval: subscription.publishing_interval,
                    monitored_items: Vec::new(),
                }
            }).collect();

            // session.subscriptions.iterate ...
            let session_id = session.session_id.to_string();
            Connection {
                id: session_id,
                // creation time
                // state
                client_name: String::from("fixme"),
                client_ip: String::from("fixme"),
                subscriptions,
            }
        }).collect();
    }
}
