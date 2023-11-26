// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::{collections::BTreeSet, sync::Arc};

use log::{debug, trace};
use parking_lot::Mutex;

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
        let running_components = self.running_components.lock();
        running_components.iter().cloned().collect()
    }

    pub fn register_component(&self, key: &str) {
        debug!("registering component {}", key);
        let mut running_components = self.running_components.lock();
        if running_components.contains(key) {
            trace!("Shouldn't be registering component {} more than once", key);
        } else {
            running_components.insert(key.to_string());
        }
    }

    pub fn deregister_component(&self, key: &str) {
        debug!("deregistering component {}", key);
        let mut running_components = self.running_components.lock();
        if !running_components.contains(key) {
            trace!(
                "Shouldn't be deregistering component {} which doesn't exist",
                key
            );
        } else {
            running_components.remove(key);
        }
    }
}
