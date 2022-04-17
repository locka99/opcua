// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Provides debug metric of server state that can be used by anything that wants
//! to see what is happening in the server. State is updated by the server as sessions are added, removed,
//! and when subscriptions / monitored items are added, removed.

use crate::runtime_components;
use crate::types::DateTime;

use crate::server::{
    comms::transport::{Transport, TransportState},
    config,
    diagnostics::ServerDiagnostics,
    server,
    state::ServerState,
    subscriptions::subscriptions,
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
    pub sessions: Vec<Session>,
    // creation time
    // state
    pub client_address: String,
    pub transport_state: String,
}

#[derive(Serialize)]
pub struct Session {
    pub id: String,
    pub session_activated: bool,
    pub session_terminated: bool,
    pub session_terminated_at: String,
    pub subscriptions: subscriptions::Metrics,
}

impl Default for ServerMetrics {
    fn default() -> Self {
        // Sample metrics
        Self {
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
}

impl ServerMetrics {
    pub fn new() -> ServerMetrics {
        Self::default()
    }

    pub fn set_server_info(&mut self, server: &server::Server) {
        let server_state = server.server_state();
        let config = {
            let server_state = trace_read_lock!(server_state);
            server_state.config.clone()
        };
        let mut config = {
            let config = trace_read_lock!(config);
            config.clone()
        };
        // For security, blank out user tokens
        config.user_tokens.clear();
        config.user_tokens.insert(
            String::new(),
            config::ServerUserToken {
                user: String::from("User identity tokens have been removed"),
                pass: None,
                x509: None,
                thumbprint: None,
            },
        );
        self.config = Some(config);
    }

    // Update the server state metrics (uptime etc.)
    pub fn update_from_server_state(&mut self, server_state: &ServerState) {
        let start_time = &server_state.start_time;
        let now = DateTime::now();

        self.server.start_time = start_time.as_chrono().to_rfc3339();

        // Take a snapshot of the diagnostics
        {
            let diagnostics = trace_read_lock!(server_state.diagnostics);
            self.diagnostics = diagnostics.clone();
        }

        let elapsed = now
            .as_chrono()
            .signed_duration_since(start_time.as_chrono());
        self.server.uptime_ms = elapsed.num_milliseconds();
    }

    // Update the connection metrics which includes susbcriptions and monitored items
    pub fn update_from_connections(&mut self, connections: server::Connections) {
        self.runtime_components = runtime_components!();
        self.connections = connections
            .iter()
            .map(|c| {
                // Carefully extract info while minimizing chance of deadlock
                let (client_address, transport_state, session_manager) = {
                    let connection = trace_read_lock!(c);
                    let client_address =
                        if let Some(ref client_address) = connection.client_address() {
                            format!("{:?}", client_address)
                        } else {
                            String::new()
                        };
                    let transport_state = match connection.state() {
                        TransportState::New => "New".to_string(),
                        TransportState::WaitingHello => "WaitingHello".to_string(),
                        TransportState::ProcessMessages => "ProcessMessages".to_string(),
                        TransportState::Finished(status_code) => {
                            format!("Finished({})", status_code)
                        }
                    };
                    (
                        client_address,
                        transport_state,
                        connection.session_manager(),
                    )
                };
                let session_manager = trace_read_lock!(session_manager);
                let sessions = session_manager
                    .sessions
                    .iter()
                    .map(|(_, session)| {
                        let session = trace_read_lock!(session);
                        let id = session.session_id().to_string();
                        let session_activated = session.is_activated();
                        let session_terminated = session.is_terminated();
                        let session_terminated_at = if session.is_terminated() {
                            session.terminated_at().to_rfc3339()
                        } else {
                            String::new()
                        };
                        let subscriptions = session.subscriptions().metrics();
                        Session {
                            id,
                            session_activated,
                            session_terminated,
                            session_terminated_at,
                            subscriptions,
                        }
                    })
                    .collect();

                // session.subscriptions.iterate ...
                Connection {
                    client_address,
                    transport_state,
                    sessions,
                }
            })
            .collect();
    }
}
