use opcua_core::types::*;
use opcua_core::comms::*;

use subscription::{Subscription};
use services::discovery::*;
use services::session::*;

/// Processes and dispatches messages for handling
pub struct MessageHandler {
    /// Number of subscriptions open for this session
    pub subscriptions: Vec<Subscription>,
    /// Discovery service
    discovery_service: DiscoveryService,
    /// Session service
    session_service: SessionService,
}

impl MessageHandler {
    pub fn new() -> MessageHandler {
        MessageHandler {
            subscriptions: Vec::new(),
            discovery_service: DiscoveryService::new(),
            session_service: SessionService::new(),
        }
    }

    pub fn handle_message(&self, message: &SupportedMessage) -> Result<SupportedMessage, &'static StatusCode> {
        let response = match *message {
            SupportedMessage::GetEndpointsRequest(ref request) => {
                self.discovery_service.handle_get_endpoints_request(request)?
            },
            SupportedMessage::CreateSessionRequest(ref request) => {
                self.session_service.handle_create_sesion_request(request)?
            }
            _ => {
                debug!("Message handler does not handle this kind of message");
                return Err(&BAD_SERVICE_UNSUPPORTED);
            }
        };
        Ok(response)
    }
}
