// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! The OPC UA Server module contains the server side functionality - address space, services,
//! server security, session management, local discovery server registration and subscriptions.
//!
//! # Usage
//!
//! An implementation will usually start by building a [`ServerConfig`], either
//! from a configuration file, or through code. Then it will construct a [`Server`], initialise
//! its address space, and then run it.
//!
//! [`Server`]: ./server/struct.Server.html
//! [`ServerConfig`]: ./config/struct.ServerConfig.html
//!
//! # Example
//!
//! This is a very simple server which runs with the default address space on the default port.
//!
//!  ```no_run
//!  use opcua::server::prelude::*;
//!
//!  fn main() {
//!      let server: Server = ServerBuilder::new_sample().server().unwrap();
//!      server.run();
//!  }
//!  ```

/// Returns true of the Option<Vec<Foo>> is None or the vec inside is empty. This is particularly
/// used by services where the spec says "All Services with arrays of operations in the request
/// shall return a bad code in the serviceResult if the array is empty."
macro_rules! is_empty_option_vec {
    ( $v: expr ) => {
        $v.is_none() || $v.as_ref().unwrap().is_empty()
    };
}

mod identity_token;
mod services;

#[cfg(feature = "discovery-server-registration")]
mod discovery;

mod session_diagnostics;

#[cfg(feature = "http")]
pub mod http;

pub mod address_space;
pub mod builder;
pub mod callbacks;
pub mod comms;
pub mod config;
pub mod continuation_point;
pub mod diagnostics;
#[macro_use]
pub mod events;
pub mod historical;
pub mod metrics;
pub mod server;
pub mod session;
pub mod state;
pub mod subscriptions;
pub mod util;

pub mod prelude {
    //! Provides a way to use most types and functions commonly used by server implementations from a
    //! single use statement.
    pub use crate::core::prelude::*;
    pub use crate::crypto::*;
    pub use crate::server::{
        address_space::types::*,
        address_space::{AccessLevel, EventNotifier, UserAccessLevel},
        builder::*,
        callbacks::*,
        config::*,
        events::event::*,
        historical::*,
        server::*,
        subscriptions::*,
        util::*,
    };
    pub use crate::types::service_types::*;
    pub use crate::types::status_code::StatusCode;
    pub use crate::types::*;
}

pub mod constants {
    //! Provides constants that govern the internal workings of the server implementation.
    /// The default hello timeout period in seconds
    pub const DEFAULT_HELLO_TIMEOUT_SECONDS: u32 = 5;
    /// Default OPC UA server port for this implementation
    pub const DEFAULT_RUST_OPC_UA_SERVER_PORT: u16 = 4855;
    /// Default maximum number of subscriptions in a session
    pub const DEFAULT_MAX_SUBSCRIPTIONS: usize = 100;
    /// Default maximum number of monitored items per subscription
    pub const DEFAULT_MAX_MONITORED_ITEMS_PER_SUB: usize = 1000;
    /// Default, well known address for TCP discovery server
    pub const DEFAULT_DISCOVERY_SERVER_URL: &str = "opc.tcp://localhost:4840/UADiscovery";

    // Internally controlled values

    /// The polling interval in millis on subscriptions and monitored items. The more
    /// fine-grained this is, the more often subscriptions will be checked for changes. The minimum
    /// publish interval cannot be less than this.
    pub const SUBSCRIPTION_TIMER_RATE_MS: u64 = 100;
    /// Minimum publishing interval for subscriptions
    pub const MIN_PUBLISHING_INTERVAL: f64 = (SUBSCRIPTION_TIMER_RATE_MS as f64) / 1000.0;
    /// Minimum sampling interval on monitored items
    pub const MIN_SAMPLING_INTERVAL: f64 = (SUBSCRIPTION_TIMER_RATE_MS as f64) / 1000.0;
    /// Maximum data change queue allowed by clients on monitored items
    pub const MAX_DATA_CHANGE_QUEUE_SIZE: usize = 10;
    /// The default size of preallocated vecs of monitored items per subscription
    pub const DEFAULT_MONITORED_ITEM_CAPACITY: usize = 100;
    /// Interval to check for HELLO timeout in millis. This can be fairly coarse because it's not
    /// something that requires huge accuracy.
    pub const HELLO_TIMEOUT_POLL_MS: u64 = 500;
    /// Maximum time in MS that a session can be inactive before a timeout
    pub const MAX_SESSION_TIMEOUT: f64 = 60000f64;
    /// Maximum size in bytes that a request message is allowed to be
    pub const MAX_REQUEST_MESSAGE_SIZE: u32 = 32768;
    /// Default keep alive count
    pub const DEFAULT_KEEP_ALIVE_COUNT: u32 = 10;
    /// Maximum keep alive count
    pub const MAX_KEEP_ALIVE_COUNT: u32 = 30000;
    /// Maximum browse continuation points
    pub const MAX_BROWSE_CONTINUATION_POINTS: usize = 20;
    /// Maximum history continuation points
    pub const MAX_HISTORY_CONTINUATION_POINTS: usize = 10;
    /// Maximum query continuation points
    pub const MAX_QUERY_CONTINUATION_POINTS: usize = 10;

    /// Maximum number of nodes in a TranslateBrowsePathsToNodeIdsRequest
    pub const MAX_NODES_PER_TRANSLATE_BROWSE_PATHS_TO_NODE_IDS: usize = 10;
    pub const MAX_NODES_PER_READ: usize = 50;
    pub const MAX_NODES_PER_WRITE: usize = 10;
    pub const MAX_NODES_PER_METHOD_CALL: usize = 10;
    pub const MAX_NODES_PER_BROWSE: usize = 50;
    pub const MAX_NODES_PER_REGISTER_NODES: usize = 10;
    /// Maximum number of nodes / references per node manaument operation
    pub const MAX_NODES_PER_NODE_MANAGEMENT: usize = 100;
    pub const MAX_MONITORED_ITEMS_PER_CALL: usize = 10;
    pub const MAX_NODES_PER_HISTORY_READ_DATA: usize = 10;
    pub const MAX_NODES_PER_HISTORY_READ_EVENTS: usize = 10;
    pub const MAX_NODES_PER_HISTORY_UPDATE_DATA: usize = 10;
    pub const MAX_NODES_PER_HISTORY_UPDATE_EVENTS: usize = 10;
}

#[cfg(test)]
mod tests;
