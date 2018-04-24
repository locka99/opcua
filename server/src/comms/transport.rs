use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use opcua_types::status_codes::StatusCode;

use session::Session;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TransportState {
    New,
    WaitingHello,
    ProcessMessages,
    Finished,
}

pub trait Transport {
    // Get the current state of the transport
    fn state(&self) -> TransportState;
    // Test if the transport has received its HELLO
    fn has_received_hello(&self) -> bool {
        match self.state() {
            TransportState::New | TransportState::WaitingHello => false,
            _ => true
        }
    }
    // Test if the transport is finished
    fn is_finished(&self) -> bool {
        self.state() == TransportState::Finished
    }
    /// Gets the session status
    fn session_status(&self) -> StatusCode;
    /// Sets the session status
    fn set_session_status(&mut self, session_status: StatusCode);
    /// Gets the session associated with the transport
    fn session(&self) -> Arc<RwLock<Session>>;
    /// Returns the address of the client (peer) of this connection
    fn client_address(&self) -> Option<SocketAddr>;
    /// Terminate the session and put the connection in a finished state
    fn terminate_session(&mut self, status_code: StatusCode);
    /// Test if the session is terminated
    fn is_session_terminated(&self) -> bool;
}
