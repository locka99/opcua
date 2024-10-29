// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

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
//! use std::time::Duration;
//! use opcua::client::{ClientBuilder, IdentityToken, Session, DataChangeCallback, MonitoredItem};
//! use opcua::types::{
//!     EndpointDescription, MessageSecurityMode, UserTokenPolicy, StatusCode,
//!     NodeId, TimestampsToReturn, MonitoredItemCreateRequest, DataValue
//! };
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
//!     // Create the session and event loop
//!     let (session, event_loop) = client.new_session_from_endpoint(endpoint, IdentityToken::Anonymous).await.unwrap();
//!     let handle = event_loop.spawn();
//!
//!     session.wait_for_connection().await;
//!
//!     // Create a subscription and monitored items
//!     if subscribe_to_values(&session).await.is_ok() {
//!         handle.await.unwrap();
//!     } else {
//!         println!("Error creating subscription");
//!     }
//! }
//!
//! async fn subscribe_to_values(session: &Session) -> Result<(), StatusCode> {
//!     // Create a subscription polling every 2s with a callback
//!     let subscription_id = session.create_subscription(
//!         Duration::from_secs(2),
//!         10,
//!         30,
//!         0,
//!         0,
//!         true,
//!         DataChangeCallback::new(
//!             |value, monitored_item| {
//!                 println!("Data change from server:");
//!                 print_value(value, monitored_item);
//!             }
//!         )
//!     ).await?;
//!     // Create some monitored items
//!     let items_to_create: Vec<MonitoredItemCreateRequest> = ["v1", "v2", "v3", "v4"].iter()
//!         .map(|v| NodeId::new(2, *v).into()).collect();
//!     let _ = session.create_monitored_items(subscription_id, TimestampsToReturn::Both, items_to_create).await?;
//!     Ok(())
//! }
//!
//! fn print_value(data_value: DataValue, item: &MonitoredItem) {
//!    let node_id = &item.item_to_monitor().node_id;
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

mod builder;
mod config;
mod retry;
mod session;
mod transport;

use std::path::PathBuf;

pub use builder::ClientBuilder;
pub use config::{ClientConfig, ClientEndpoint, ClientUserToken, ANONYMOUS_USER_TOKEN_ID};
pub use session::{
    Client, DataChangeCallback, EventCallback, MonitoredItem, OnSubscriptionNotification, Session,
    SessionActivity, SessionConnectMode, SessionEventLoop, SessionPollResult, Subscription,
    SubscriptionActivity, SubscriptionCallbacks,
};
pub use transport::AsyncSecureChannel;

#[derive(Debug, Clone)]
pub enum IdentityToken {
    /// Anonymous identity token
    Anonymous,
    /// User name and a password
    UserName(String, String),
    /// X5090 cert - a path to the cert.der, and private.pem
    X509(PathBuf, PathBuf),
}
