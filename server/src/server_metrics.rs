//! The server metrics module maintains a snapshot of server state that can be used by anything that wants
//! to see what is happening in the server. State is updated by the server as sessions are added, removed,
//! and when subscriptions / monitored items are added, removed.

use comms::tcp_transport::TcpTransport;
use config;
use opcua_types::DateTime;
use server;
use server_state;
use session;
use std::collections::BTreeMap;


#[derive(Serialize)]
pub struct ServerMetrics {
    pub server: Server,
    pub server_config: Option<config::ServerConfig>,
    pub sessions: BTreeMap<u32, Session>,
}

#[derive(Serialize)]
pub struct Server {
    pub start_time: String,
    pub uptime_ms: i64,

}

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
            server: Server {
                start_time: String::new(),
                uptime_ms: 0,
            },
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
        server_config.user_tokens.insert(String::new(), config::ServerUserToken {
            user: String::from("User identity tokens have been removed"),
            pass: None,
        });
        self.server_config = Some(server_config.clone());
    }

    pub fn update_from_server_state(&mut self, server_state: &server_state::ServerState) {
        let start_time = &server_state.start_time;
        let now = DateTime::now();

        self.server.start_time = start_time.as_chrono().to_rfc2822();

        let elapsed = now.as_chrono().signed_duration_since(start_time.as_chrono());
        self.server.uptime_ms = elapsed.num_milliseconds();
    }

    pub fn update_from_connections(&mut self, connections: &Vec<TcpTransport>) {
        self.sessions.clear();
        connections.iter().for_each(|c| {
            let session_id = {
                let session = c.session();
                let session = session.read().unwrap();
                // TODO
                0
            };

            // session.subscriptions.iterate ...

            let sessions_metric = Session {
                id: session_id,
                // creation time
                // state
                client_name: String::from("fixme"),
                client_ip: String::from("fixme"),
                subscriptions: Vec::new(),
            };


            self.sessions.insert(0, sessions_metric);
        });
    }
}
