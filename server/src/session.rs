use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use opcua_core::types::*;
use opcua_core::comms::*;

use types::*;

/// Session info holds information about a session created by CreateSession service
#[derive(Clone)]
pub struct SessionInfo {}

/// Session state is anything associated with the session at the message / service level
#[derive(Clone)]
pub struct SessionState {
    pub session_info: Option<SessionInfo>,
    pub subscriptions: Arc<Mutex<HashMap<UInt32, Subscription>>>,
    pub publish_request_queue: Vec<PublishRequest>
}

impl SessionState {
    pub fn new() -> SessionState {
        SessionState {
            session_info: None,
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
            publish_request_queue: Vec::new(),
        }
    }

    pub fn poll_subscriptions(&self, session_state: &mut SessionState) -> Option<Vec<SupportedMessage>> {
        let subscriptions = session_state.subscriptions.lock().unwrap();
        for (_, subscription) in subscriptions.iter() {
            match subscription.state {
                SubscriptionState::Closed => {
                    // DO NOTHING
                },
                SubscriptionState::Creating => {
                    // DO NOTHING
                },
                SubscriptionState::Normal => {
                    // DO NOTHING
                },
                SubscriptionState::KeepAlive => {
                    // DO NOTHING
                },
                SubscriptionState::Late => {
                    // DO NOTHING
                },
            }
        }

        None
    }
}
