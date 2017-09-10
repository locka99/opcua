use std::sync::MutexGuard;

use prelude::*;
use comms::tcp_transport::*;
use server::ServerState;

use tests::*;

struct TestState {
    tcp_transport: TcpTransport,
}

impl TestState {
    pub fn new() -> TestState {
        let server = Server::new(ServerConfig::default_anonymous());
        TestState {
            tcp_transport: TcpTransport::new(server.server_state),
        }
    }

    pub fn get_server_state_and_session(&self) -> (MutexGuard<ServerState>, MutexGuard<Session>) {
        (self.tcp_transport.server_state.lock().unwrap(),
         self.tcp_transport.session.lock().unwrap())
    }
}

// Attribute service tests
// Discovery service tests
// Monitored item service tests
// Session service tests
// Subscription service tests

mod view;