use std::collections::HashSet;

use opcua_types::UInt32;

use subscriptions::subscription::Subscription;
use session::Session;

/// Structure that captures diagnostics information for the server
#[derive(Clone, Serialize, Debug)]
pub struct ServerDiagnostics {
    pub session_count: UInt32,
    pub session_count_cumulative: UInt32,
    pub active_subscriptions: HashSet<UInt32>,
    pub subscription_count_cumulative: UInt32,
}

impl ServerDiagnostics {
    pub fn new() -> ServerDiagnostics {
        ServerDiagnostics {
            session_count: 0,
            session_count_cumulative: 0,
            active_subscriptions: HashSet::new(),
            subscription_count_cumulative: 0,
        }
    }

    pub fn on_create_session(&mut self, _session: &Session) {
        self.session_count += 1;
        self.session_count_cumulative += 1;
    }

    pub fn on_destroy_session(&mut self, _session: &Session) {
        self.session_count -= 1;
    }

    pub fn on_create_subscription(&mut self, subscription: &Subscription) {
        self.active_subscriptions.insert(subscription.subscription_id);
        self.subscription_count_cumulative += 1;
    }

    pub fn on_destroy_subscription(&mut self, subscription: &Subscription) {
        let _ = self.active_subscriptions.remove(&subscription.subscription_id);
    }
}

