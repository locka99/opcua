use std::result::Result;

use opcua_core::types::*;

use comms::*;

pub struct SessionState {
    /// The endpoint url
    pub endpoint_url: String,
    /// Session timeout in milliseconds
    pub session_timeout: u32,
    pub send_buffer_size: usize,
    pub receive_buffer_size: usize,
    pub max_message_size: usize,

}

impl SessionState {}

pub struct Session {
    /// Runtime state of the session, reset if disconnected
    pub session_state: SessionState,
    /// Transport layer
    transport: TcpTransport,
}

impl Session {
    pub fn new(endpoint_url: &str) -> Session {
        Session {
            session_state: SessionState {
                endpoint_url: endpoint_url.to_string(),
                session_timeout: 60 * 1000,
                send_buffer_size: 65536,
                receive_buffer_size: 65536,
                max_message_size: 65536,
            },
            transport: TcpTransport::new()
        }
    }

    pub fn connect(&mut self) -> Result<(), &'static StatusCode> {
        let session_state = &mut self.session_state;

        let _ = self.transport.connect(session_state)?;
        let _ = self.transport.send_hello(session_state)?;
        // Send create session
        // Send activate session

        Ok(())
    }

    pub fn disconnect(&mut self) {
        self.transport.disconnect();
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