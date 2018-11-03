//! The OPC UA Server module contains all server side functionality - address space, services,
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
//! This is a minimal server which runs with the default address space on the default port.
//! 
//!  ```rust,no_run
//!  extern crate opcua_types;
//!  extern crate opcua_core;
//!  extern crate opcua_server;
//! 
//!  use opcua_server::prelude::*;
//! 
//!  fn main() {
//!      let server: Server = ServerBuilder::new_sample().server().unwrap();
//!      server.run();
//!  }
//!  ```
extern crate chrono;
#[cfg(feature = "http")]
extern crate hyper;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate bitflags;


#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate time;
extern crate futures;
extern crate tokio;
extern crate tokio_io;
extern crate tokio_codec;
extern crate tokio_timer;

extern crate opcua_client;
#[macro_use]
extern crate opcua_core;
extern crate opcua_types;

type DateTimeUtc = chrono::DateTime<chrono::Utc>;

lazy_static! {
    static ref RUNTIME: diagnostics::Runtime = diagnostics::Runtime::default();
}

#[macro_export]
macro_rules! register_runtime_component {
    ( $component_name:expr ) => {
        use crate::RUNTIME;
        RUNTIME.register_component($component_name);
    }
}

#[macro_export]
macro_rules! deregister_runtime_component {
    ( $component_name:expr ) => {
        use crate::RUNTIME;
        RUNTIME.deregister_component($component_name);
    }
}

mod services;
mod session;
mod discovery;
mod completion_pact;

pub mod comms;
pub mod metrics;
pub mod server;
pub mod builder;
pub mod state;
pub mod diagnostics;
pub mod subscriptions;
pub mod config;
pub mod address_space;
pub mod util;
pub mod continuation_point;
#[cfg(feature = "http")]
pub mod http;

pub mod prelude {
    //! Provides a way to use most types and functions commonly used by server implementations from a
    //! single use statement.
    pub use opcua_types::status_code::StatusCode;
    pub use opcua_types::service_types::*;
    pub use opcua_core::prelude::*;
    pub use crate::{
        config::*,
        server::*,
        builder::*,
        address_space::types::*,
        subscriptions::*,
        subscriptions::subscription::*,
        subscriptions::monitored_item::*,
        util::*,
    };
}

pub mod constants {
    //! Provides constants that govern the internal workings of the server implementation.
    /// The default hello timeout period in seconds
    pub const DEFAULT_HELLO_TIMEOUT_SECONDS: u32 = 120;
    /// Default OPC UA server port for this implementation
    pub const DEFAULT_RUST_OPC_UA_SERVER_PORT: u16 = 4855;
    /// Default maximum number of subscriptions in a session
    pub const DEFAULT_MAX_SUBSCRIPTIONS: u32 = 100;
    /// Default, well known address for TCP discovery server
    pub const DEFAULT_DISCOVERY_SERVER_URL: &str = "opc.tcp://localhost:4840/UADiscovery";

    // Internally controlled values

    /// The polling interval in millis on subscriptions and monitored items. The more
    /// finegrained this is, the more often subscriptions will be checked for changes. The minimum
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
    /// Time in MS that a session will timeout after with inactivity
    pub const SESSION_TIMEOUT: f64 = 50000f64;
    /// Maximum size in bytes that a request message is allowed to be
    pub const MAX_REQUEST_MESSAGE_SIZE: u32 = 32768;
    /// Default keep alive count
    pub const DEFAULT_KEEP_ALIVE_COUNT: u32 = 10;
    /// Maxmimum keep alive count
    pub const MAX_KEEP_ALIVE_COUNT: u32 = 30000;
    /// Maximum browse continuation points
    pub const MAX_BROWSE_CONTINUATION_POINTS: usize = 10;
    /// Maximum history continuation points
    pub const MAX_HISTORY_CONTINUATION_POINTS: usize = 0;
    /// Maximum query continuation points
    pub const MAX_QUERY_CONTINUATION_POINTS: usize = 0;
    /// Maximum method calls per request
    pub const MAX_METHOD_CALLS: usize = 10;
}

#[cfg(test)]
mod tests;
