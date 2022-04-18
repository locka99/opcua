// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! The OPC UA Client module contains the functionality necessary for a client to connect to an OPC UA server,
//! authenticate itself, send messages, receive responses, get values, browse the address space and
//! provide callbacks for things to be propagated to the client.
//!
//! A client has to specify the endpoint description they wish to connect to, security policy and other
//! configurable options, e.g. paths to PKI keys. All of this is encapsulated in a [`Client`] object.
//!
//! One of these may be made programatically using a [`ClientBuilder`] or from a preexisting [`ClientConfig`]
//! which can be loaded fully or partially from disk. Use the way that suits you.
//!
//! Once the `Client` is created it can connect to a server by creating a [`Session`]. Multiple sessions
//! can be created from the same client. Functions on the [`Session`] correspond to OPC UA services so
//! it can be used to:
//!
//! * Discover endpoints
//! * Activate a session
//! * Create / modify / delete subscriptions
//! * Create / modify / delete monitored items
//! * Read and write values
//! * Browse the address space
//! * Add or remove nodes
//!
//! Functionality is synchronous and housekeeping such as renewing the active session and sending publish requests is
//! handled automatically.
//!
//! Data change and event notifications are via asynchronous callbacks.
//!
//! # Example
//!
//! Here is a complete example of a client that connects to the `samples/simple-server`, subscribes
//! to some values and prints out changes to those values. This example corresponds to the one
//! described in the in docs/client.md tutorial.
//!
//! ```no_run
//! use std::sync::Arc;
//! use opcua::async_client::prelude::*;
//! use opcua::sync::*;
//!
//! #[tokio::main]
//! async fn main() {
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
//!     let session = client.connect_to_endpoint(endpoint, IdentityToken::Anonymous).await.unwrap();
//!
//!     // Create a subscription and monitored items
//!     if subscribe_to_values(session.clone()).await.is_ok() {
//!         let _ = Session::run(session);
//!     } else {
//!         println!("Error creating subscription");
//!     }
//! }
//!
//! async fn subscribe_to_values(session: Arc<RwLock<Session>>) -> Result<(), StatusCode> {
//!     let mut session = session.write();
//!     // Create a subscription polling every 2s with a callback
//!     let subscription_id = session.create_subscription(2000.0, 10, 30, 0, 0, true, DataChangeCallback::new(|changed_monitored_items| {
//!         println!("Data change from server:");
//!         changed_monitored_items.iter().for_each(|item| print_value(item));
//!     })).await?;
//!     // Create some monitored items
//!     let items_to_create: Vec<MonitoredItemCreateRequest> = ["v1", "v2", "v3", "v4"].iter()
//!         .map(|v| NodeId::new(2, *v).into()).collect();
//!     let _ = session.create_monitored_items(subscription_id, TimestampsToReturn::Both, &items_to_create).await?;
//!     Ok(())
//! }
//!
//! fn print_value(item: &MonitoredItem) {
//!    let node_id = &item.item_to_monitor().node_id;
//!    let data_value = item.last_value();
//!    if let Some(ref value) = data_value.value {
//!        println!("Item \"{}\", Value = {:?}", node_id, value);
//!    } else {
//!        println!("Item \"{}\", Value not found, error: {}", node_id, data_value.status.as_ref().unwrap());
//!    }
//!}
//! ```
//!
//! [`Client`]: ./async_client/struct.Client.html
//! [`ClientConfig`]: ./config/struct.ClientConfig.html
//! [`ClientBuilder`]: ./async_client_builder/struct.ClientBuilder.html
//! [`Session`]: ./session/struct.Session.html

use crate::core::supported_message::SupportedMessage;
use crate::types::{response_header::ResponseHeader, status_code::StatusCode};

mod comms;
mod message_queue;
mod subscription;
mod subscription_state;

// Use through prelude
mod builder;
mod callbacks;
mod client;
mod config;
mod session;
mod session_retry_policy;

/// Process the service result, i.e. where the request "succeeded" but the response
/// contains a failure status code.
pub(crate) fn process_service_result(response_header: &ResponseHeader) -> Result<(), StatusCode> {
    if response_header.service_result.is_bad() {
        info!(
            "Received a bad service result {} from the request",
            response_header.service_result
        );
        Err(response_header.service_result)
    } else {
        Ok(())
    }
}

pub(crate) fn process_unexpected_response(response: SupportedMessage) -> StatusCode {
    match response {
        SupportedMessage::ServiceFault(service_fault) => {
            error!(
                "Received a service fault of {} for the request",
                service_fault.response_header.service_result
            );
            service_fault.response_header.service_result
        }
        _ => {
            error!("Received an unexpected response to the request");
            StatusCode::BadUnknownResponse
        }
    }
}

pub mod prelude {
    pub use crate::{
        core::prelude::*,
        crypto::*,
        types::{service_types::*, status_code::StatusCode},
    };

    pub use crate::async_client::{
        builder::*,
        callbacks::*,
        client::*,
        config::*,
        session::{services::*, session::*},
        subscription::MonitoredItem,
    };
}

#[cfg(test)]
mod tests;
