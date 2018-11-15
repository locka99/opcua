//! Provides diagnostics structures and functions for gathering information about the running
//! state of a server.
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use opcua_client::prelude::ServerDiagnosticsSummaryDataType;

use crate::{
    subscriptions::subscription::Subscription,
    session::Session,
};

pub struct Runtime {
    /// This is a list of the currently running components / threads / tasks in the server,
    /// useful for debugging.
    running_components: Arc<Mutex<BTreeSet<String>>>,
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            running_components: Arc::new(Mutex::new(BTreeSet::new())),
        }
    }
}

impl Runtime {
    pub fn components(&self) -> Vec<String> {
        let running_components = trace_lock_unwrap!(self.running_components);
        running_components.iter().map(|k| k.clone()).collect()
    }

    pub fn register_component<T>(&self, name: T) where T: Into<String> {
        let mut running_components = trace_lock_unwrap!(self.running_components);
        let key = name.into();
        if running_components.contains(&key) {
            error!("Shouldn't be registering component {} more than once", key);
        }
        running_components.insert(key);
    }

    pub fn deregister_component<T>(&self, name: T) where T: Into<String> {
        let mut running_components = trace_lock_unwrap!(self.running_components);
        let key = name.into();
        if !running_components.contains(&key) {
            error!("Shouldn't be deregistering component {} which doesn't exist", key);
        }
        running_components.remove(&key);
    }
}

/// Structure that captures diagnostics information for the server
#[derive(Clone, Serialize, Debug)]
pub struct ServerDiagnostics {
    /// This is a live summary of the server diagnostics
    server_diagnostics_summary: ServerDiagnosticsSummaryDataType,
}

const SERVER_DIAGNOSTICS: &'static str = "ServerDiagnostics";

impl Default for ServerDiagnostics {
    fn default() -> Self {
        register_runtime_component!(SERVER_DIAGNOSTICS);
        Self {
            server_diagnostics_summary: ServerDiagnosticsSummaryDataType::default(),
        }
    }
}

impl Drop for ServerDiagnostics {
    fn drop(&mut self) {
        deregister_runtime_component!(SERVER_DIAGNOSTICS);
    }
}

impl ServerDiagnostics {
    /// Return a completed summary of the server diagnostics as they stand. This structure
    /// is used to fill the address space stats about the server.
    pub fn server_diagnostics_summary(&self) -> &ServerDiagnosticsSummaryDataType {
        &self.server_diagnostics_summary
    }

    pub fn on_rejected_security_session(&mut self) {
        self.server_diagnostics_summary.security_rejected_session_count += 1;
    }

    pub fn on_rejected_session(&mut self) {
        self.server_diagnostics_summary.rejected_session_count += 1;
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
        self.server_diagnostics_summary.current_subscription_count -= 1;
    }

    // --- These are not yet called by anything

    pub fn on_server_view(&mut self, _session: &Session) {
        self.server_diagnostics_summary.server_view_count += 1;
        unimplemented!();
    }

    pub fn on_session_timeout(&mut self, _session: &Session) {
        self.server_diagnostics_summary.session_timeout_count += 1;
        unimplemented!()
    }

    pub fn on_session_abort(&mut self, _session: &Session) {
        self.server_diagnostics_summary.session_abort_count += 1;
        unimplemented!()
    }

    pub fn on_publishing_interval(&mut self) {
        self.server_diagnostics_summary.publishing_interval_count += 1;
        unimplemented!()
    }

    pub fn on_security_rejected_request(&mut self) {
        self.server_diagnostics_summary.security_rejected_requests_count += 1;
        unimplemented!()
    }

    pub fn on_rejected_request(&mut self) {
        self.server_diagnostics_summary.rejected_requests_count += 1;
        unimplemented!()
    }
}

