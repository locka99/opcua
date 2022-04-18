// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Defines the traits and other agnostic properties that all OPC UA transports will share.
//! Provides a level of abstraction for the server to call through when it doesn't require specific
//! knowledge of the transport it is using.

use std::{net::SocketAddr, sync::Arc};

use crate::sync::*;
use crate::types::status_code::StatusCode;

use crate::server::session::SessionManager;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TransportState {
    New,
    WaitingHello,
    ProcessMessages,
    Finished(StatusCode),
}

/// Represents a transport layer, the thing responsible for maintaining an open channel and transferring
/// data between the server and the client.
pub trait Transport {
    // Get the current state of the transport
    fn state(&self) -> TransportState;
    // Test if the transport has received its HELLO
    fn has_received_hello(&self) -> bool {
        !matches!(
            self.state(),
            TransportState::New | TransportState::WaitingHello
        )
    }
    /// Terminate the session and put the connection in a finished state
    fn finish(&mut self, status_code: StatusCode);
    // Test if the transport is finished
    fn is_finished(&self) -> bool {
        matches!(self.state(), TransportState::Finished(_))
    }
    /// Returns the address of the client (peer) of this connection
    fn client_address(&self) -> Option<SocketAddr>;
    /// Returns the session map for the connection
    fn session_manager(&self) -> Arc<RwLock<SessionManager>>;
}
