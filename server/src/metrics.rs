//! Provides debug metric of server state that can be used by anything that wants
//! to see what is happening in the server. State is updated by the server as sessions are added, removed,
//! and when subscriptions / monitored items are added, removed.

use opcua_types::DateTime;

use crate::{
    comms::transport::Transport,
    config,
    diagnostics::ServerDiagnostics,
    server,
    state::ServerState,
    subscriptions::subscriptions::{self},
};

#[derive(Serialize)]
pub struct ServerMetrics {
    pub server: Server,
    pub diagnostics: ServerDiagnostics,
    pub config: Option<config::ServerConfig>,
    pub connections: Vec<Connection>,
    pub runtime_components: Vec<String>,
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
    pub client_address: String,
    pub transport_state: String,
    pub session_activated: bool,
    pub session_terminated: bool,
    pub session_terminated_at: String,
    pub subscriptions: subscriptions::Metrics,
}

impl ServerMetrics {
    pub fn new() -> ServerMetrics {
        // Sample metrics
        ServerMetrics {
            server: Server {
                start_time: String::new(),
                uptime_ms: 0,
            },
            diagnostics: ServerDiagnostics::default(),
            config: None,
            connections: Vec::new(),
            runtime_components: Vec::new(),
        }
    }

    pub fn set_server_info(&mut self, server: &server::Server) {
        let server_state = server.server_state();
        let config = {
            let server_state = trace_read_lock_unwrap!(server_state);
            server_state.config.clone()
        };
        let mut config = {
            let config = trace_read_lock_unwrap!(config);
            config.clone()
        };
        // For security, blank out user tokens
        config.user_tokens.clear();
        config.user_tokens.insert(String::new(), config::ServerUserToken {
            user: String::from("User identity tokens have been removed"),
            pass: None,
            x509: None,
            thumbprint: None,
        });
        self.config = Some(config.clone());
    }

    // Update the server state metrics (uptime etc.)
    pub fn update_from_server_state(&mut self, server_state: &ServerState) {
        let start_time = &server_state.start_time;
        let now = DateTime::now();

        self.server.start_time = start_time.as_chrono().to_rfc3339();

        // Take a snapshot of the diagnostics
        {
            let diagnostics = trace_read_lock_unwrap!(server_state.diagnostics);
            self.diagnostics = diagnostics.clone();
        }

        let elapsed = now.as_chrono().signed_duration_since(start_time.as_chrono());
        self.server.uptime_ms = elapsed.num_milliseconds();
    }

    // Update the connection metrics which includes susbcriptions and monitored items
    pub fn update_from_connections(&mut self, connections: &server::Connections) {
        self.runtime_components = runtime_components!();

        self.connections = connections.iter().map(|c| {

            // Carefully extract info while minimizing chance of deadlock

            let (client_address, transport_state, session) = {
                let connection = trace_read_lock_unwrap!(c);
                let client_address = if connection.client_address().is_some() {
                    format!("{:?}", connection.client_address().as_ref().unwrap())
                } else {
                    String::new()
                };
                let transport_state = format!("{:?}", connection.state());
                (client_address, transport_state, connection.session())
            };
            let (id, session_activated, session_terminated, session_terminated_at, subscriptions) = {
                let session = trace_read_lock_unwrap!(session);
                let id = session.session_id.to_string();
                let session_activated = session.activated;
                let session_terminated = session.terminated();
                let session_terminated_at = if session.terminated() {
                    session.terminated_at().to_rfc3339()
                } else {
                    String::new()
                };
                let subscriptions = session.subscriptions.metrics();
                (id, session_activated, session_terminated, session_terminated_at, subscriptions)
            };

            // session.subscriptions.iterate ...
            Connection {
                id,
                client_address,
                transport_state,
                session_activated,
                session_terminated,
                session_terminated_at,
                subscriptions,
            }
        }).collect();
    }
}
