// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

//! Provides utility routines for things that might be used in a number of places elsewhere.

use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use opcua_types::service_types::ServerState as ServerStateType;

use crate::state::ServerState;

/// This is a convenience for a polling action. This struct starts a repeating timer that calls
/// an action repeatedly.
pub struct PollingAction {}

impl PollingAction {
    pub fn spawn<F>(
        server_state: Arc<RwLock<ServerState>>,
        interval_ms: u64,
        action: F,
    ) -> PollingAction
    where
        F: 'static + Fn() + Send,
    {
        let server_state_take_while = server_state.clone();
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now(),
            Duration::from_millis(interval_ms),
        );
        let task = async move {
            loop {
                interval.tick().await;
                {
                    trace!("polling action.take_while");
                    let server_state = trace_read_lock_unwrap!(server_state_take_while);
                    // If the server aborts or is in a failed state, this polling timer will stop
                    let abort = match server_state.state() {
                        ServerStateType::Failed
                        | ServerStateType::NoConfiguration
                        | ServerStateType::Shutdown => true,
                        _ => server_state.is_abort(),
                    };
                    if abort {
                        debug!("Polling action is stopping due to server state / abort");
                        return;
                    }
                }
                // Polling timer will only call the action if the server is in a running state
                let process_action = {
                    let server_state = trace_read_lock_unwrap!(server_state);
                    server_state.is_running()
                };
                if process_action {
                    action();
                }
            }
        };
        let _ = tokio::spawn(task);
        PollingAction {}
    }
}
