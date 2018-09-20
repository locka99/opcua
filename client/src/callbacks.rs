//! Callback managers for functions that a client can register with the OPC UA client SDK to receive
//! notifications and events.

use std::fmt;

use subscription::MonitoredItem;

/// This is the data change callback that clients register to receive item change notifications
pub(crate) struct DataChangeCallback {
    /// The actual call back
    cb: Box<dyn Fn(Vec<&MonitoredItem>) + Send + Sync + 'static>
}

impl DataChangeCallback {
    /// Constructs a callback from the supplied function
    pub(crate) fn new<CB>(cb: CB) -> DataChangeCallback where CB: Fn(Vec<&MonitoredItem>) + Send + Sync + 'static {
        DataChangeCallback {
            cb: Box::new(cb)
        }
    }

    /// Calls the call back with the data change items
    pub(crate) fn call(&self, data_change_items: Vec<&MonitoredItem>) {
        (self.cb)(data_change_items);
    }
}

/// This is the registered callback to receive connection status change notifications. The boolean
/// argument indicates that status has changed from connected to disconnected or vice versa.
pub(crate) struct ConnectionStatusCallback {
    cb: Option<Box<dyn FnMut(bool) + 'static + Send + Sync>>,
}

impl fmt::Debug for ConnectionStatusCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[callback]")
    }
}

impl ConnectionStatusCallback {
    // Constructor
    pub(crate) fn new() -> ConnectionStatusCallback {
        ConnectionStatusCallback {
            cb: None
        }
    }

    /// Sets the connection status callback to the supplied callback, or clears it if None is supplied
    /// instead.
    pub(crate) fn set_callback<CB>(&mut self, cb: Option<CB>) where CB: FnMut(bool) + 'static + Send + Sync {
        self.cb = if let Some(cb) = cb {
            Some(Box::new(cb))
        } else {
            None
        };
    }

    /// Fires a connected event, i.e. if there is a callback it calls onto the connected method.
    pub(crate) fn fire_connected(&mut self) {
        debug!("Received OPC UA connected event");
        if let Some(ref mut cb) = self.cb {
            (cb)(true);
        }
    }

    /// Fires a disconnected event, i.e. if there is a callback it calls onto the connected method.
    pub(crate) fn fire_disconnected(&mut self) {
        debug!("Received OPC UA disconnected event");
        if let Some(ref mut cb) = self.cb {
            (cb)(false);
        }
    }
}
