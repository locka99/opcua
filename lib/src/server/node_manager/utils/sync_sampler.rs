use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio_util::sync::{CancellationToken, DropGuard};

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
    _guard: DropGuard,
    token: CancellationToken,
}

impl SyncSampler {
    /// Create a new sync sampler.
    pub fn new() -> Self {
        let token = CancellationToken::new();
        Self {
            samplers: Default::default(),
            _guard: token.clone().drop_guard(),
            token,
        }
    }

    /// Start the sampler. You should avoid calling this multiple times, typically
    /// this is called in `build_nodes` or `init`. The sampler will automatically shut down
    /// once it is dropped.
    pub fn run(&self, interval: Duration, subscriptions: Arc<SubscriptionCache>) {
        let token = self.token.clone();
        let samplers = self.samplers.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = Self::run_internal(samplers, interval, subscriptions) => {},
                _ = token.cancelled() => {}
            }
        });
    }

    /// Add a periodic sampler for a monitored item.
    /// Note that if a sampler for the given nodeId/attributeId pair already exists,
    /// no new sampler will be created. It is assumed that each nodeId/attributeId
    /// pair has a single sampler function.
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

    /// Update the sample rate of a monitored item.
    /// The smallest registered sampling interval for each nodeId/attributeId pair is
    /// used. This is also bounded from below by the rate of the SyncSampler itself.
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

    /// Set the sampler mode for a node.
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

    /// Remove a sampler. The actual sampler will only be fully removed once
    /// all samplers for the attribute are gone.
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
