//! The OPC UA Client module provides the functionality necessary for a client to connect to an OPC UA server,
//! authenticate itself, send messages, receive responses, get values, browse the address space and
//! provide callbacks for things to be propagated to the client.

#[macro_use]
extern crate log;
extern crate url;
extern crate chrono;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate time;
extern crate futures;
extern crate tokio;
extern crate tokio_io;
extern crate tokio_timer;

extern crate opcua_types;
#[macro_use]
extern crate opcua_core;

mod comms;
mod subscription;
mod subscription_state;
mod session_state;

pub mod config;
pub mod client;
pub mod session;

pub mod prelude {
    pub use opcua_types::status_codes::StatusCode;
    pub use opcua_types::service_types::*;
    pub use opcua_core::prelude::*;
    pub use client::*;
    pub use config::*;
    pub use session::*;
    pub use subscription::{MonitoredItem, DataChangeCallback};
}

#[cfg(test)]
mod tests;