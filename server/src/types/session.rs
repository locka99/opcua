use std::collections::HashMap;

use opcua_core::types::*;

use types::*;

/// Session info holds information about a session created by CreateSession service
#[derive(Clone)]
pub struct SessionInfo {}

/// Session state is anything associated with the session at the message / service level
#[derive(Clone)]
pub struct SessionState {
    pub session_info: Option<SessionInfo>,
    pub subscriptions: HashMap<UInt32, Subscription>,
    pub last_subscription_id: UInt32,
    pub publish_request_queue: Vec<PublishRequest>
}

impl SessionState {
    pub fn new() -> SessionState {
        SessionState {
            session_info: None,
            subscriptions: HashMap::new(),
            publish_request_queue: Vec::new(),
            last_subscription_id: 0,
        }
    }
}
