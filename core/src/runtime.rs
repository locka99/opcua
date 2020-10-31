// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

use crate::trace_lock_unwrap;

/// The `Runtime` is for debugging / diagnostics purposes and tracks which substantial system objects
/// components are in existence. It can be used to detect if something has shutdown or not.
pub struct Runtime {
    /// This is a list of the currently running components / threads / tasks in the server,
    /// useful for debugging.
    running_components: Arc<Mutex<BTreeSet<String>>>,
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            running_components: Arc::new(Mutex::new(BTreeSet::new())),
        }
    }
}

impl Runtime {
    pub fn components(&self) -> Vec<String> {
        let running_components = trace_lock_unwrap!(self.running_components);
        running_components.iter().cloned().collect()
    }

    pub fn register_component<T>(&self, name: T)
    where
        T: Into<String>,
    {
        let key = name.into();
        debug!("registering component {}", key);
        let mut running_components = trace_lock_unwrap!(self.running_components);
        if running_components.contains(&key) {
            trace!("Shouldn't be registering component {} more than once", key);
        }
        running_components.insert(key);
    }

    pub fn deregister_component<T>(&self, name: T)
    where
        T: Into<String>,
    {
        let key = name.into();
        debug!("deregistering component {}", key);
        let mut running_components = trace_lock_unwrap!(self.running_components);
        if !running_components.contains(&key) {
            trace!(
                "Shouldn't be deregistering component {} which doesn't exist",
                key
            );
        }
        running_components.remove(&key);
    }
}
