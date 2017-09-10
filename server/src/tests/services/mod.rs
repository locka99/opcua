use std::sync::MutexGuard;

use prelude::*;
use comms::tcp_transport::*;
use server::ServerState;

use tests::*;

struct ServiceTest {
    tcp_transport: TcpTransport,
}

impl ServiceTest {
    pub fn new() -> ServiceTest {
        let server = Server::new(ServerConfig::default_anonymous());
        ServiceTest {
            tcp_transport: TcpTransport::new(server.server_state),
        }
    }

    pub fn get_server_state_and_session(&self) -> (MutexGuard<ServerState>, MutexGuard<Session>) {
        (self.tcp_transport.server_state.lock().unwrap(),
         self.tcp_transport.session.lock().unwrap())
    }
}

fn make_request_header() -> RequestHeader {
    RequestHeader {
        authentication_token: NodeId::new_numeric(0, 99),
        timestamp: DateTime::now(),
        request_handle: 1,
        return_diagnostics: 0,
        audit_entry_id: UAString::null(),
        timeout_hint: 123456,
        additional_header: ExtensionObject::null(),
    }
}

mod attribute;
mod discovery;
mod session;
mod monitored_item;
mod subscription;
mod view;