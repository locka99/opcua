//! Provides callback traits and concrete implementations that the client can use to register for notifications
//! with the client api.
//!
//! For example, the client must supply an [`OnDataChange`] implementation when it calls `Session::create_subscription`.
//! It could implement this trait for itself, or it can use the convenience implementation called `DataChangeCallback`
//! that calls a client supplied function when it triggers.
use std::fmt;

use opcua_types::status_code::StatusCode;

use crate::subscription::MonitoredItem;

pub enum SubscriptionNotification<'a> {
    DataChange(Vec<&'a MonitoredItem>),
    Event(u32 /* TODO */),
}

/// This trait is implemented by something that wishes to receive subscription data change notifications.
pub trait OnSubscriptionNotification {
    fn notification(&mut self, notification: SubscriptionNotification) {
        match notification {
            SubscriptionNotification::DataChange(data_change_items) => self.data_change(data_change_items),
            SubscriptionNotification::Event(_e) => self.event()
        }
    }

    fn data_change(&mut self, _data_change_items: Vec<&MonitoredItem>) {}
    fn event(&mut self /* TODO */) {}
}

/// This trait is implemented by something that wishes to receive connection status change notifications.
pub trait OnConnectionStatusChange {
    /// Called when the connection status changes from connected to disconnected or vice versa
    fn connection_status_change(&mut self, connected: bool);
}

pub trait OnSessionClosed {
    /// Called when the connection closed (in addition to a status change event). The status
    /// code should be checked to see if the closure was a graceful terminate (`Good`), or the result
    /// of a network or protocol error.
    ///
    /// If no session retry policy has been created for the client session, the server implementation
    /// might choose to reconnect in response to a bad status code by itself, however it should
    /// avoid retrying too quickly or indefinitely in case the error is permanent.
    fn session_closed(&mut self, status_code: StatusCode);
}

/// This is a concrete implementation of [`OnSubscriptionNotification`] that calls a function when
/// a data change occurs.
pub struct DataChangeCallback {
    /// The actual call back
    cb: Box<dyn Fn(Vec<&MonitoredItem>) + Send + Sync + 'static>
}

impl OnSubscriptionNotification for DataChangeCallback {
    fn data_change(&mut self, data_change_items: Vec<&MonitoredItem>) {
        (self.cb)(data_change_items);
    }
}

impl DataChangeCallback {
    /// Constructs a callback from the supplied function
    pub fn new<CB>(cb: CB) -> Self where CB: Fn(Vec<&MonitoredItem>) + Send + Sync + 'static {
        Self {
            cb: Box::new(cb)
        }
    }
}


/// This is a concrete implementation of [`OnSubscriptionNotification`] that calls a function
/// when an event occurs.
pub struct EventCallback {
    /// The actual call back
    cb: Box<dyn Fn() + Send + Sync + 'static>
}

impl OnSubscriptionNotification for EventCallback {
    fn event(&mut self) {
        (self.cb)();
    }
}

impl EventCallback {
    /// Constructs a callback from the supplied function
    pub fn new<CB>(cb: CB) -> Self where CB: Fn() + Send + Sync + 'static {
        Self {
            cb: Box::new(cb)
        }
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
    fn connection_status_change(&mut self, connected: bool) {
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
    pub fn new<CB>(cb: CB) -> Self where CB: FnMut(bool) + Send + Sync + 'static {
        Self {
            cb: Box::new(cb)
        }
    }
}

pub struct SessionClosedCallback {
    cb: Box<dyn FnMut(StatusCode) + Send + Sync + 'static>,
}

impl OnSessionClosed for SessionClosedCallback {
    fn session_closed(&mut self, status_code: StatusCode) {
        (self.cb)(status_code);
    }
}

impl SessionClosedCallback {
    // Constructor
    pub fn new<CB>(cb: CB) -> Self where CB: FnMut(StatusCode) + Send + Sync + 'static {
        Self {
            cb: Box::new(cb)
        }
    }
}
