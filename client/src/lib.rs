//! The OPC UA Client module contains the client side functionality necessary for a client to connect to an OPC UA server,
//! authenticate itself, send messages, receive responses, get values, browse the address space and
//! provide callbacks for things to be propagated to the client.
//!
//! Clients start off by creating a [`ClientBuilder`] and constructing a [`Client`]. From the client
//! they can connect to a server to create a [`Session`] and call functions that allow interactions with the server
//! via the session.
//!
//! It is also possible to create a `Client` from a [`ClientConfig`] that can be defined on disk, or
//! in code.
//!
//! Once a `Client` has been created, it is able to connect to an OPC UA. The connection is managed
//! by a [`Session`]'s functions that enable the client to create subscriptions, monitor items,
//! browse the address space and so on.
//!
//! # Example
//!
//! Here is a complete example of a client that connects to the `samples/simple-server`, subscribes
//! to some values and prints out changes to those values. This example corresponds to the one
//! described in the in docs/client.md tutorial.
//!
//! ```no_run
//! use std::sync::{Arc, RwLock};
//! use opcua_client::prelude::*;
//!
//! fn main() {
//!     let mut client = ClientBuilder::new()
//!         .application_name("My First Client")
//!         .application_uri("urn:MyFirstClient")
//!         .create_sample_keypair(true)
//!         .trust_server_certs(false)
//!         .session_retry_limit(3)
//!         .client().unwrap();
//!
//!     // Create an endpoint. The EndpointDescription can be made from a tuple consisting of
//!     // the endpoint url, security policy, message security mode and user token policy.
//!     let endpoint: EndpointDescription = ("opc.tcp://localhost:4855/", "None", MessageSecurityMode::None, UserTokenPolicy::anonymous()).into();
//!
//!     // Create the session
//!     let session = client.connect_to_endpoint(endpoint, IdentityToken::Anonymous).unwrap();
//!
//!     // Create a subscription and monitored items
//!     if subscribe_to_values(session.clone()).is_ok() {
//!         let _ = Session::run(session);
//!     } else {
//!         println!("Error creating subscription");
//!     }
//! }
//!
//! fn subscribe_to_values(session: Arc<RwLock<Session>>) -> Result<(), StatusCode> {
//!     let mut session = session.write().unwrap();
//!     // Create a subscription polling every 2s with a callback
//!     let subscription_id = session.create_subscription(2000.0, 10, 30, 0, 0, true, DataChangeCallback::new(|changed_monitored_items| {
//!         println!("Data change from server:");
//!         changed_monitored_items.iter().for_each(|item| print_value(item));
//!     }))?;
//!     // Create some monitored items
//!     let items_to_create: Vec<MonitoredItemCreateRequest> = ["v1", "v2", "v3", "v4"].iter()
//!         .map(|v| NodeId::new(2, *v).into()).collect();
//!     let _ = session.create_monitored_items(subscription_id, TimestampsToReturn::Both, &items_to_create)?;
//!     Ok(())
//! }
//!
//! fn print_value(item: &MonitoredItem) {
//!    let node_id = &item.item_to_monitor().node_id;
//!    let data_value = item.value();
//!    if let Some(ref value) = data_value.value {
//!        println!("Item \"{}\", Value = {:?}", node_id, value);
//!    } else {
//!        println!("Item \"{}\", Value not found, error: {}", node_id, data_value.status.as_ref().unwrap());
//!    }
//!}
//! ```
//!
//! [`Client`]: ./client/struct.Client.html
//! [`ClientConfig`]: ./config/struct.ClientConfig.html
//! [`ClientBuilder`]: ./client_builder/struct.ClientBuilder.html
//! [`Session`]: ./session/struct.Session.html
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate opcua_core;

mod comms;
mod subscription;
mod subscription_state;
mod subscription_timer;
mod session_state;
mod message_queue;

// Use through prelude
mod config;
mod client;
mod session;
mod callbacks;
mod builder;
mod session_retry;

use opcua_types::{SupportedMessage, service_types::ResponseHeader, status_code::StatusCode};

/// Process the service result, i.e. where the request "succeeded" but the response
/// contains a failure status code.
pub(crate) fn process_service_result(response_header: &ResponseHeader) -> Result<(), StatusCode> {
    if response_header.service_result.is_bad() {
        info!("Received a bad service result {} from the request", response_header.service_result);
        Err(response_header.service_result)
    } else {
        Ok(())
    }
}

pub(crate) fn process_unexpected_response(response: SupportedMessage) -> StatusCode {
    match response {
        SupportedMessage::ServiceFault(service_fault) => {
            error!("Received a service fault of {} for the request", service_fault.response_header.service_result);
            service_fault.response_header.service_result
        }
        _ => {
            error!("Received an unexpected response to the request");
            StatusCode::BadUnknownResponse
        }
    }
}

pub mod prelude {
    pub use opcua_types::{status_code::StatusCode, service_types::*};
    pub use opcua_core::prelude::*;
    pub use crate::{
        client::*,
        builder::*,
        config::*,
        session::*,
        subscription::MonitoredItem,
        callbacks::*,
    };
}

#[cfg(test)]
mod tests;