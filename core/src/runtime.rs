use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

use crate::trace_lock_unwrap;

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

    pub fn register_component<T>(&self, name: T) where T: Into<String> {
        let mut running_components = trace_lock_unwrap!(self.running_components);
        let key = name.into();
        if running_components.contains(&key) {
            trace!("Shouldn't be registering component {} more than once", key);
        }
        running_components.insert(key);
    }

    pub fn deregister_component<T>(&self, name: T) where T: Into<String> {
        let mut running_components = trace_lock_unwrap!(self.running_components);
        let key = name.into();
        if !running_components.contains(&key) {
            trace!("Shouldn't be deregistering component {} which doesn't exist", key);
        }
        running_components.remove(&key);
    }
}
