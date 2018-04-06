use opcua_types::UInt32;

use subscriptions::subscription::Subscription;
use session::Session;

/// Structure that captures diagnostics information for the server
#[derive(Clone, Serialize, Debug)]
pub struct ServerDiagnostics {
    pub session_count: UInt32,
    pub session_count_cumulative: UInt32,
    pub subscription_count: UInt32,
    pub subscription_count_cumulative: UInt32,
}

impl ServerDiagnostics {
    pub fn new() -> ServerDiagnostics {
        ServerDiagnostics {
            session_count: 0,
            session_count_cumulative: 0,
            subscription_count: 0,
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

    pub fn on_create_subscription(&mut self, _subscription: &Subscription) {
        self.subscription_count += 1;
        self.subscription_count_cumulative += 1;
    }

    pub fn on_destroy_subscription(&mut self, _subscription: &Subscription) {
        self.subscription_count -= 1;
    }
}

