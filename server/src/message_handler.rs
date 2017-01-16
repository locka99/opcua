use opcua_core::types::*;
use opcua_core::comms::*;

use subscription::{Subscription};
use services::discovery::*;

/// Processes and dispatches messages for handling
pub struct MessageHandler {
    /// Number of subscriptions open for this session
    pub subscriptions: Vec<Subscription>,
    /// Discovery service
    discovery_service: DiscoveryService,
}

impl MessageHandler {
    pub fn new() -> MessageHandler {
        MessageHandler {
            subscriptions: Vec::new(),
            discovery_service: DiscoveryService {},
        }
    }

    pub fn handle_message(&self, message: &SupportedMessage) -> Result<SupportedMessage, &'static StatusCode> {
        let response = match *message {
            SupportedMessage::GetEndpointsRequest(ref request) => {
                self.discovery_service.handle_get_endpoints_request(request)?
            },
            _ => {
                debug!("Message handler does not handle this kind of message");
                return Err(&BAD_SERVICE_UNSUPPORTED);
            }
        };
        Ok(response)
    }
}
