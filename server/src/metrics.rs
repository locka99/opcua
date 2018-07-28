//! The server metrics module maintains a snapshot of server state that can be used by anything that wants
//! to see what is happening in the server. State is updated by the server as sessions are added, removed,
//! and when subscriptions / monitored items are added, removed.

use opcua_types::DateTime;

use comms::transport::Transport;
use config;
use server;
use subscriptions::subscription::Subscription;
use diagnostics::ServerDiagnostics;
use state::ServerState;

#[derive(Serialize)]
pub struct ServerMetrics {
    pub server: Server,
    pub diagnostics: ServerDiagnostics,
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
    pub client_address: String,
    pub transport_state: String,
    pub session_activated: bool,
    pub session_terminated: bool,
    pub session_terminated_at: String,
    pub subscriptions: Vec<Subscription>,
}

impl ServerMetrics {
    pub fn new() -> ServerMetrics {
        // Sample metrics
        ServerMetrics {
            server: Server {
                start_time: String::new(),
                uptime_ms: 0,
            },
            diagnostics: ServerDiagnostics::new(),
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
        self.connections = connections.iter().map(|c| {
            let connection = trace_read_lock_unwrap!(c);

            let session = connection.session();
            let session = trace_read_lock_unwrap!(session);

            // Subscriptions
            let subscriptions = session.subscriptions.subscriptions().iter().map(|subscription_pair| {
                subscription_pair.1.clone()
            }).collect();

            // session.subscriptions.iterate ...
            let session_id = session.session_id.to_string();
            Connection {
                id: session_id,
                // creation time
                // state
                client_address: if connection.client_address().is_some() {
                    format!("{:?}", connection.client_address().as_ref().unwrap())
                } else {
                    String::new()
                },
                transport_state: format!("{:?}", connection.state()),
                session_activated: session.activated,
                session_terminated: session.terminated,
                session_terminated_at: if session.terminated {
                    session.terminated_at.to_rfc3339()
                } else {
                    String::new()
                },
                subscriptions,
            }
        }).collect();
    }
}
