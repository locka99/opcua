//! The server metrics module maintains a snapshot of server state that can be used by anything that wants
//! to see what is happening in the server. State is updated by the server as sessions are added, removed,
//! and when subscriptions / monitored items are added, removed.

use config;
use server;
use server_state;
use session;
use std::collections::BTreeMap;


#[derive(Serialize)]
pub struct ServerMetrics {
    pub server: Option<Server>,
    pub server_config: Option<config::ServerConfig>,
    pub sessions: BTreeMap<u32, Session>,
}

#[derive(Serialize)]
pub struct Server {}

#[derive(Serialize)]
pub struct Session {
    pub id: u32,
    // creation time
    // state
    pub client_name: String,
    pub client_ip: String,
    pub subscriptions: Vec<Subscription>,
}

#[derive(Serialize)]
pub struct Subscription {
    id: u32,
    // interval
    // publishing enabled
    // monitored items
}

impl ServerMetrics {
    pub fn new() -> ServerMetrics {
        // Sample metrics
        ServerMetrics {
            server: Some(Server {}),
            server_config: None,
            sessions: BTreeMap::new(),
        }
    }

    pub fn set_server_info(&mut self, server: &server::Server) {
        let server_state = trace_read_lock_unwrap!(server.server_state);
        let server_config = trace_read_lock_unwrap!(server_state.config);

        // For security, blank out user tokens
        let mut server_config = server_config.clone();
        server_config.user_tokens.clear();

        self.server_config = Some(server_config.clone());
        self.add_session();
    }

    pub fn update_from_server_state(&mut self, server_state: &server_state::ServerState) {
        // TODO update the metrics using the sessions and subscriptions in this file.
    }

    pub fn add_session(&mut self) { // , _session: session::Session) {
        self.sessions.insert(1, Session {
            id: 1,
            client_name: String::from("bar"),
            client_ip: String::from("123.0.0.1"),
            subscriptions: vec![
                Subscription {
                    id: 100,
                }
            ],
        });
    }

    pub fn remove_session(&mut self, subscription_id: u32) {
        self.sessions.remove(&subscription_id);
    }
}
