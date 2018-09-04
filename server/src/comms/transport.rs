//! Defines the traits and other agnostic properties that all OPC UA transports will share.
//! Provides a level of abstraction for the server to call through when it doesn't require specific
//! knowledge of the transport it is using.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use opcua_types::status_code::StatusCode;

use session::Session;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TransportState {
    New,
    WaitingHello,
    ProcessMessages,
    Finished(StatusCode),
}

/// Represents a transport layer, the thing responsible for maintaining an open channel and transferring
/// data between the server and the client.
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
    /// Terminate the session and put the connection in a finished state
    fn finish(&mut self, status_code: StatusCode);
    // Test if the transport is finished
    fn is_finished(&self) -> bool {
        if let TransportState::Finished(_) = self.state() {
            true
        } else {
            false
        }
    }
    /// Gets the session associated with the transport
    fn session(&self) -> Arc<RwLock<Session>>;
    /// Returns the address of the client (peer) of this connection
    fn client_address(&self) -> Option<SocketAddr>;
    /// Test if the session is terminated
    fn is_session_terminated(&self) -> bool;
}
