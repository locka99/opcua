// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Provides utility routines for things that might be used in a number of places elsewhere.

use std::sync::Arc;

use tokio::time::{interval_at, Duration, Instant};

use crate::sync::*;
use crate::types::service_types::ServerState as ServerStateType;

use crate::server::state::ServerState;

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
        tokio::spawn(async move {
            let mut timer = interval_at(Instant::now(), Duration::from_millis(interval_ms));
            loop {
                {
                    // trace!("polling action.take_while");
                    let server_state = trace_read_lock!(server_state);
                    // If the server aborts or is in a failed state, this polling timer will stop
                    let abort = match server_state.state() {
                        ServerStateType::Failed
                        | ServerStateType::NoConfiguration
                        | ServerStateType::Shutdown => true,
                        _ => server_state.is_abort(),
                    };
                    if abort {
                        debug!("Polling action is stopping due to server state / abort");
                        break;
                    }
                }

                // Timer
                timer.tick().await;

                // Polling timer will only call the action if the server is in a running state
                let process_action = {
                    let server_state = trace_read_lock!(server_state);
                    server_state.is_running()
                };
                if process_action {
                    action();
                }
            }
        });
        PollingAction {}
    }
}
