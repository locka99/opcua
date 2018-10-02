//! The OPC UA Client module provides the functionality necessary for a client to connect to an OPC UA server,
//! authenticate itself, send messages, receive responses, get values, browse the address space and
//! provide callbacks for things to be propagated to the client.
//!
//! Clients start off by creating a [`ClientBuilder`] and constructing a [`Client`] from that.
//!
//! It is also possible to create a `Client` from a [`ClientConfig`] that can be defined on disk, or
//! in code.
//!
//! Once a `Client` has been created, it is able to connect to an OPC UA. The connection is managed
//! by a [`Session`] and hasfunctions that enable the client to create subscriptions, monitor items,
//! browse the address space and so on.
//!
//! [`Client`]: ./client/struct.Client.html
//! [`ClientConfig`]: ./config/struct.ClientConfig.html
//! [`ClientBuilder`]: ./client_builder/struct.ClientBuilder.html
//! [`Session`]: ./session/struct.Session.html

#[macro_use]
extern crate log;
extern crate url;
extern crate chrono;
#[macro_use]
extern crate serde_derive;


extern crate futures;
extern crate tokio;
extern crate tokio_io;
extern crate tokio_timer;
extern crate tokio_codec;

extern crate opcua_types;
#[macro_use]
extern crate opcua_core;

mod comms;
mod subscription;
mod subscription_state;
mod session_state;
mod message_queue;

// Use through prelude
mod config;
mod client;
mod session;
mod callbacks;
mod builder;

use opcua_types::SupportedMessage;
use opcua_types::service_types::ResponseHeader;
use opcua_types::status_code::StatusCode;

/// Process the service result, i.e. where the request "succeeded" but the response
/// contains a failure status code.
pub(crate) fn process_service_result(response_header: &ResponseHeader) -> Result<(), StatusCode> {
    if response_header.service_result.is_bad() {
        info!("Received a bad service result {:?} from the request", response_header.service_result);
        Err(response_header.service_result)
    } else {
        Ok(())
    }
}

pub(crate) fn process_unexpected_response(response: SupportedMessage) -> StatusCode {
    match response {
        SupportedMessage::ServiceFault(service_fault) => {
            error!("Received a service fault of {:?} for the request", service_fault.response_header.service_result);
            service_fault.response_header.service_result
        }
        _ => {
            error!("Received an unexpected response to the request");
            StatusCode::BadUnknownResponse
        }
    }
}

pub mod prelude {
    pub use opcua_types::status_code::StatusCode;
    pub use opcua_types::service_types::*;
    pub use opcua_core::prelude::*;
    pub use client::*;
    pub use builder::*;
    pub use config::*;
    pub use session::*;
    pub use subscription::MonitoredItem;
    pub use callbacks::*;
}

#[cfg(test)]
mod tests;