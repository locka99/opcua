use opcua_core::types::*;
use opcua_core::comms::*;

use subscription::{Subscription};
use services::discovery::*;

/// Processes and dispatches messages for handling
pub struct MessageHandler {
    /// Number of subscriptions open for this session
    pub subscriptions: Vec<Subscription>,
}

impl MessageHandler {
    pub fn new() -> MessageHandler {
        MessageHandler {
            subscriptions: Vec::new(),
        }
    }

    pub fn handle_message(message: &mut SupportedMessage) -> Result<Vec<SupportedMessage>, &'static StatusCode> {
        Err(&BAD_REQUEST_NOT_ALLOWED)
    }
}
