//! Provides diagnostics structures and functions for gathering information about the running
//! state of a server.
use opcua_client::prelude::ServerDiagnosticsSummaryDataType;

use subscriptions::subscription::Subscription;
use session::Session;

/// Structure that captures diagnostics information for the server
#[derive(Clone, Serialize, Debug)]
pub struct ServerDiagnostics {
    server_diagnostics_summary: ServerDiagnosticsSummaryDataType,
}

impl Default for ServerDiagnostics {
    fn default() -> Self {
        Self {
            server_diagnostics_summary: ServerDiagnosticsSummaryDataType::default()
        }
    }
}

impl ServerDiagnostics {
    /// Return a completed summary of the server diagnostics as they stand. This structure
    /// is used to fill the address space stats about the server.
    pub fn server_diagnostics_summary(&self) -> ServerDiagnosticsSummaryDataType {
        self.server_diagnostics_summary.clone()
    }

    pub fn on_rejected_request(&mut self) {
        self.server_diagnostics_summary.rejected_requests_count += 1;
    }

    pub fn on_create_session(&mut self, _session: &Session) {
        self.server_diagnostics_summary.current_session_count += 1;
        self.server_diagnostics_summary.cumulated_session_count += 1;
    }

    pub fn on_destroy_session(&mut self, _session: &Session) {
        self.server_diagnostics_summary.current_session_count -= 1;
    }

    pub fn on_create_subscription(&mut self, _subscription: &Subscription) {
        self.server_diagnostics_summary.current_subscription_count += 1;
        self.server_diagnostics_summary.cumulated_subscription_count += 1;
    }

    pub fn on_destroy_subscription(&mut self, _subscription: &Subscription) {
        self.server_diagnostics_summary.current_subscription_count -=1;
    }
}

