// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Provides callback traits and concrete implementations that the client can use to register for notifications
//! with the client api.
//!
//! For example, the client must supply an [`OnSubscriptionNotification`] implementation when it calls `Session::create_subscription`.
//! It could implement this trait for itself, or it can use the concrete implementations in [`DataChangeCallback`] and [`EventCallback`].
//!
//! [`DataChangeCallback`]: ./struct.DataChangeCallback.html
//! [`EventCallback`]: ./struct.EventCallback.html

use std::fmt;

use crate::types::{service_types::EventNotificationList, status_code::StatusCode};

use super::subscription::MonitoredItem;

/// The `OnSubscriptionNotification` trait is the callback registered along with a new subscription to
/// receive subscription notification callbacks.
///
/// Unless your subscription contains a mix of items which are monitoring data and events
/// you probably only need to implement either `data_change()`, or `event()` and leave the default,
/// no-op implementation for the other.
///
/// There are concrete implementations of this trait in [`DataChangeCallback`] and [`EventCallback`].
///
/// [`DataChangeCallback`]: ./struct.DataChangeCallback.html
/// [`EventCallback`]: ./struct.EventCallback.html
///
pub trait OnSubscriptionNotification {
    /// Called by the subscription after a `DataChangeNotification`. The default implementation
    /// does nothing.
    fn on_data_change(&mut self, _data_change_items: &[&MonitoredItem]) {}

    /// Called by the subscription after a `EventNotificationList`. The notifications contained within
    /// are individual `EventFieldList` structs filled from the select clause criteria from when the
    /// event was constructed. The default implementation does nothing.
    fn on_event(&mut self, _events: &EventNotificationList) {}
}

/// The `OnConnectionStatusChange` trait can be used to register on the session to be notified
/// of connection status change notifications.
pub trait OnConnectionStatusChange {
    /// Called when the connection status changes from connected to disconnected or vice versa
    fn on_connection_status_change(&mut self, connected: bool);
}

/// The `OnSessionClosed` trait can be used to register on a session and called to notify the client
/// that the session has closed.
pub trait OnSessionClosed {
    /// Called when the connection closed (in addition to a status change event). The status
    /// code should be checked to see if the closure was a graceful terminate (`Good`), or the result
    /// of a network or protocol error.
    ///
    /// If no session retry policy has been created for the client session, the server implementation
    /// might choose to reconnect in response to a bad status code by itself, however it should
    /// avoid retrying too quickly or indefinitely in case the error is permanent.
    fn on_session_closed(&mut self, status_code: StatusCode);
}

/// This is a concrete implementation of [`OnSubscriptionNotification`] that calls a function when
/// a data change occurs.
pub struct DataChangeCallback {
    /// The actual call back
    cb: Box<dyn Fn(&[&MonitoredItem]) + Send + Sync + 'static>,
}

impl OnSubscriptionNotification for DataChangeCallback {
    fn on_data_change(&mut self, data_change_items: &[&MonitoredItem]) {
        (self.cb)(data_change_items);
    }
}

impl DataChangeCallback {
    /// Constructs a callback from the supplied function
    pub fn new<CB>(cb: CB) -> Self
    where
        CB: Fn(&[&MonitoredItem]) + Send + Sync + 'static,
    {
        Self { cb: Box::new(cb) }
    }
}

/// This is a concrete implementation of [`OnSubscriptionNotification`] that calls a function
/// when an event occurs.
pub struct EventCallback {
    /// The actual call back
    cb: Box<dyn Fn(&EventNotificationList) + Send + Sync + 'static>,
}

impl OnSubscriptionNotification for EventCallback {
    fn on_event(&mut self, events: &EventNotificationList) {
        (self.cb)(events);
    }
}

impl EventCallback {
    /// Constructs a callback from the supplied function
    pub fn new<CB>(cb: CB) -> Self
    where
        CB: Fn(&EventNotificationList) + Send + Sync + 'static,
    {
        Self { cb: Box::new(cb) }
    }
}

/// This is a concrete implementation of [`OnConnectionStatusChange`] that calls the supplied function.
pub struct ConnectionStatusCallback {
    cb: Box<dyn FnMut(bool) + Send + Sync + 'static>,
}

impl fmt::Debug for ConnectionStatusCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[callback]")
    }
}

impl OnConnectionStatusChange for ConnectionStatusCallback {
    fn on_connection_status_change(&mut self, connected: bool) {
        if connected {
            debug!("Received OPC UA connected event");
        } else {
            debug!("Received OPC UA disconnected event");
        }
        (self.cb)(connected);
    }
}

impl ConnectionStatusCallback {
    // Constructor
    pub fn new<CB>(cb: CB) -> Self
    where
        CB: FnMut(bool) + Send + Sync + 'static,
    {
        Self { cb: Box::new(cb) }
    }
}

/// This is a concrete implementation of `OnSessionClosed` that will call the supplied
/// function.
pub struct SessionClosedCallback {
    cb: Box<dyn FnMut(StatusCode) + Send + Sync + 'static>,
}

impl OnSessionClosed for SessionClosedCallback {
    fn on_session_closed(&mut self, status_code: StatusCode) {
        (self.cb)(status_code);
    }
}

impl SessionClosedCallback {
    // Constructor
    pub fn new<CB>(cb: CB) -> Self
    where
        CB: FnMut(StatusCode) + Send + Sync + 'static,
    {
        Self { cb: Box::new(cb) }
    }
}
