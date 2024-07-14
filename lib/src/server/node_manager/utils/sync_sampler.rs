use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::task::JoinHandle;

use crate::{
    server::{MonitoredItemHandle, SubscriptionCache},
    sync::Mutex,
    types::{AttributeId, DataValue, MonitoringMode, NodeId},
};

struct ItemRef {
    mode: MonitoringMode,
    sampling_interval: Duration,
}

struct SamplerItem {
    sampler: Box<dyn FnMut() -> Option<DataValue> + Send>,
    sampling_interval: Duration,
    last_sample: Instant,
    enabled: bool,
    items: HashMap<MonitoredItemHandle, ItemRef>,
}

impl SamplerItem {
    pub fn refresh_values(&mut self) {
        let mut interval = Duration::MAX;
        let mut enabled = false;
        for item in self.items.values() {
            if item.mode != MonitoringMode::Disabled {
                if interval > item.sampling_interval {
                    interval = item.sampling_interval;
                }
                enabled = true;
            }
        }
        self.sampling_interval = interval;
        self.enabled = enabled;
        if self.last_sample > (Instant::now() + self.sampling_interval) {
            self.last_sample = Instant::now() + self.sampling_interval;
        }
    }
}

/// Utility for periodically sampling a list of nodes/attributes.
/// When using this you should call `run` to start the sampler once you have access
/// to the server context.
pub struct SyncSampler {
    samplers: Arc<Mutex<HashMap<(NodeId, AttributeId), SamplerItem>>>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for SyncSampler {
    fn drop(&mut self) {
        // Lock must be possible since we have a unique reference to the mutex,
        // unless we are panicking.
        let Some(lock) = self.handle.try_lock() else {
            return;
        };

        if let Some(handle) = lock.as_ref() {
            handle.abort();
        }
    }
}

impl SyncSampler {
    pub fn new() -> Self {
        Self {
            samplers: Default::default(),
            handle: Default::default(),
        }
    }

    pub fn run(&self, interval: Duration, subscriptions: Arc<SubscriptionCache>) {
        let handle = {
            let samplers = self.samplers.clone();
            tokio::spawn(Self::run_internal(samplers, interval, subscriptions))
        };
        let mut lock = self.handle.lock();
        if let Some(old_handle) = lock.take() {
            old_handle.abort();
        }
        *lock = Some(handle);
    }

    pub fn add_sampler(
        &self,
        node_id: NodeId,
        attribute: AttributeId,
        sampler: impl FnMut() -> Option<DataValue> + Send + 'static,
        mode: MonitoringMode,
        handle: MonitoredItemHandle,
        sampling_interval: Duration,
    ) {
        let mut samplers = self.samplers.lock();
        let id = (node_id, attribute);
        let sampler = samplers.entry(id).or_insert(SamplerItem {
            sampler: Box::new(sampler),
            sampling_interval,
            last_sample: Instant::now(),
            items: HashMap::new(),
            enabled: false,
        });
        sampler.items.insert(
            handle,
            ItemRef {
                mode,
                sampling_interval,
            },
        );
        sampler.refresh_values();
    }

    pub fn update_sampler(
        &self,
        node_id: &NodeId,
        attribute: AttributeId,
        handle: MonitoredItemHandle,
        sampling_interval: Duration,
    ) {
        let mut samplers = self.samplers.lock();
        if let Some(sampler) = samplers.get_mut(&(node_id.clone(), attribute)) {
            if let Some(item) = sampler.items.get_mut(&handle) {
                item.sampling_interval = sampling_interval;
                sampler.refresh_values();
            }
        }
    }

    pub fn set_sampler_mode(
        &self,
        node_id: &NodeId,
        attribute: AttributeId,
        handle: MonitoredItemHandle,
        mode: MonitoringMode,
    ) {
        let mut samplers = self.samplers.lock();
        if let Some(sampler) = samplers.get_mut(&(node_id.clone(), attribute)) {
            if let Some(item) = sampler.items.get_mut(&handle) {
                item.mode = mode;
                sampler.refresh_values();
            }
        }
    }

    pub fn remove_sampler(
        &self,
        node_id: &NodeId,
        attribute: AttributeId,
        handle: MonitoredItemHandle,
    ) {
        let mut samplers = self.samplers.lock();
        let id = (node_id.clone(), attribute);

        let Some(sampler) = samplers.get_mut(&id) else {
            return;
        };
        sampler.items.remove(&handle);
        if sampler.items.is_empty() {
            samplers.remove(&id);
        }
    }

    async fn run_internal(
        samplers: Arc<Mutex<HashMap<(NodeId, AttributeId), SamplerItem>>>,
        interval: Duration,
        subscriptions: Arc<SubscriptionCache>,
    ) {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let now = Instant::now();
            let mut samplers = samplers.lock();
            let values = samplers
                .iter_mut()
                .filter_map(|((node_id, attribute), sampler)| {
                    if !sampler.enabled {
                        return None;
                    }
                    if sampler.last_sample + sampler.sampling_interval > now {
                        return None;
                    }
                    let Some(value) = (sampler.sampler)() else {
                        return None;
                    };
                    sampler.last_sample = now;
                    Some((value, node_id, *attribute))
                });
            subscriptions.notify_data_change(values);
        }
    }
}
