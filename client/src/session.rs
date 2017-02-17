use std::result::Result;

use opcua_core::types::*;

pub struct SessionState {}

impl SessionState {
    pub fn new() -> SessionState {
        SessionState {}
    }
}

pub struct Session {
    /// The endpoint url
    pub endpoint_url: String,
    /// Session timeout in milliseconds
    pub session_timeout: u32,
    /// Runtime state of the session, reset if disconnected
    pub session_state: SessionState,
    // application description
    // user identity token
    // user security policy
    // tcp transport
}

impl Session {
    pub fn new(endpoint_url: &str) -> Session {
        Session {
            endpoint_url: endpoint_url.to_string(),
            session_timeout: 60 * 1000,
            session_state: SessionState::new()
        }
    }

    pub fn connect(&mut self) -> Result<(), StatusCode> {
        // Send hello
        // Send create session
        // Send activate session
        Err(BAD_NOT_IMPLEMENTED.clone())
    }

    pub fn disconnect(&mut self) {
        // Disconnect
    }

    /// Synchronously browses the nodes specified in the list of browse descriptions
    pub fn browse(&mut self) {
        // Send browse_request
    }

    /// Synchronously browses a single node
    pub fn browse_node(&mut self) {
        // Send browse request for one node
    }

    /// Synchronously reads values from the server
    pub fn read(&mut self) {
        // Read a bunch of values
    }

    /// Synchronously writes values to the server
    pub fn write(&mut self) {
        // Write to a bunch of values
    }
}