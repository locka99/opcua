// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Provides diagnostics structures and functions for gathering information about the running
//! state of a server.

use crate::types::service_types::ServerDiagnosticsSummaryDataType;
use crate::{deregister_runtime_component, register_runtime_component};

use crate::core::RUNTIME;

use super::{session::Session, subscriptions::subscription::Subscription};

/// Structure that captures di                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          agnostics information for the server
#[derive(Clone, Serialize, Debug)]
pub struct ServerDiagnostics {
    /// This is a live summary of the server diagnostics
    server_diagnostics_summary: ServerDiagnosticsSummaryDataType,
}

const SERVER_DIAGNOSTICS: &str = "ServerDiagnostics";

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

    /// Increment the number of requests that were rejected due to security constraints since the server was
    /// started (or restarted). The requests include all Services defined in Part 4, also requests
    /// to create sessions.
    pub(crate) fn on_rejected_security_session(&mut self) {
        self.server_diagnostics_summary
            .security_rejected_session_count += 1;
    }

    /// Increment the number of requests that were rejected since the server was started (or restarted). The
    /// requests include all Services defined in Part 4, also requests to create sessions. This
    /// number includes the securityRejectedRequestsCount.
    pub(crate) fn on_rejected_session(&mut self) {
        self.server_diagnostics_summary.rejected_session_count += 1;
    }

    /// Increment the number of client sessions currently established in the server.
    pub(crate) fn on_create_session(&mut self, _session: &Session) {
        self.server_diagnostics_summary.current_session_count += 1;
        self.server_diagnostics_summary.cumulated_session_count += 1;
        debug!(
            "Incrementing current session count to {}",
            self.server_diagnostics_summary.current_session_count
        );
    }

    /// Decrement the number of client sessions currently established in the server.
    pub(crate) fn on_destroy_session(&mut self, _session: &Session) {
        self.server_diagnostics_summary.current_session_count -= 1;
        debug!(
            "Decrementing current session count to {}",
            self.server_diagnostics_summary.current_session_count
        );
    }

    /// Increment the number of subscriptions currently established in the server.
    pub(crate) fn on_create_subscription(&mut self, _subscription: &Subscription) {
        self.server_diagnostics_summary.current_subscription_count += 1;
        self.server_diagnostics_summary.cumulated_subscription_count += 1;
    }

    /// Decrement the number of subscriptions currently established in the server.
    pub(crate) fn on_destroy_subscription(&mut self, _subscription: &Subscription) {
        self.server_diagnostics_summary.current_subscription_count -= 1;
    }

    /// Increment the number of client sessions that were closed due to timeout since the server was started (or restarted).
    pub(crate) fn on_session_timeout(&mut self) {
        self.server_diagnostics_summary.session_timeout_count += 1;
    }

    // --- These are not yet called by anything

    /*
    /// Increment the number of server-created views in the server.
    pub(crate) fn on_server_view(&mut self, _session: &Session) {
        self.server_diagnostics_summary.server_view_count += 1;
        unimplemented!();
    }

    /// Increment the number of client sessions that were closed due to errors since the server was started (or restarted).
    pub(crate) fn on_session_abort(&mut self, _session: &Session) {
        self.server_diagnostics_summary.session_abort_count += 1;
        unimplemented!()
    }

    /// Increment the number of publishing intervals currently supported in the server.
    pub(crate) fn on_publishing_interval(&mut self) {
        self.server_diagnostics_summary.publishing_interval_count += 1;
        unimplemented!()
    }

    /// Increment the number of requests that were rejected due to security constraints since the server was
    /// started (or restarted). The requests include all Services defined in Part 4, also requests
    /// to create sessions.
    pub fn on_security_rejected_request(&mut self) {
        self.server_diagnostics_summary.security_rejected_requests_count += 1;
        unimplemented!()
    }

    /// Increment the number of requests that were rejected since the server was started (or restarted). The
    /// requests include all Services defined in Part 4, also requests to create sessions. This
    /// number includes the securityRejectedRequestsCount.
    pub(crate) fn on_rejected_request(&mut self) {
        self.server_diagnostics_summary.rejected_requests_count += 1;
        unimplemented!()
    }
    */
}
