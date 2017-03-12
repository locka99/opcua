//! The OPC UA client crate provides the functionality necessary for a client to connect to an OPC server,
//! authenticate itself, send messages, receive responses, get values, browse the address space and
//! provide callbacks for things to be propagated to the client.

#[macro_use]
extern crate log;
extern crate url;
extern crate chrono;

extern crate opcua_core;

mod comms;

pub mod client;
pub mod session;

pub mod prelude {
    pub use opcua_core::prelude::*;
    pub use client::*;
    pub use session::*;
}
