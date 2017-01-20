use std::sync::{Arc, Mutex};

use opcua_core::types::*;
use opcua_core::comms::*;

use subscription::{Subscription};
use services::discovery::*;
use services::session::*;
use server::ServerState;

/// Processes and dispatches messages for handling
pub struct MessageHandler {
    /// Server state
    server_state: Arc<Mutex<ServerState>>,
    /// Discovery service
    discovery_service: DiscoveryService,
    /// Session service
    session_service: SessionService,
}

impl MessageHandler {
    pub fn new(server_state: &Arc<Mutex<ServerState>>) -> MessageHandler {
        MessageHandler {
            server_state: server_state.clone(),
            discovery_service: DiscoveryService::new(),
            session_service: SessionService::new(),
        }
    }

    pub fn handle_message(&self, message: &SupportedMessage) -> Result<SupportedMessage, &'static StatusCode> {
        let mut server_state = self.server_state.lock().unwrap();
        let response = match *message {
            SupportedMessage::GetEndpointsRequest(ref request) => {
                self.discovery_service.handle_get_endpoints_request(&mut server_state, request)?
            },
            SupportedMessage::CreateSessionRequest(ref request) => {
                self.session_service.handle_create_sesion_request(&mut server_state, request)?
            }
            _ => {
                debug!("Message handler does not handle this kind of message");
                return Err(&BAD_SERVICE_UNSUPPORTED);
            }
        };
        Ok(response)
    }
}
