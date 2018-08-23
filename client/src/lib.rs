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

use opcua_types::{SupportedMessage};
use opcua_types::service_types::ResponseHeader;
use opcua_types::status_codes::StatusCode;

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