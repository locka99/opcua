use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::task::JoinHandle;

use crate::{
    server::SubscriptionCache,
    types::{AttributeId, DataValue, NodeId},
    sync::Mutex,
};

struct SamplerItem {
    sampler: Box<dyn FnMut() -> Option<DataValue> + Send>,
    sampling_interval: Duration,
    last_sample: Instant,
    item_count: usize,
}

/// Utility for periodically sampling a list of nodes/attributes.
/// When using this you should call `run` to start the sampler once you have access
/// to the
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

    pub fn add_or_update_sampler(
        &self,
        node_id: NodeId,
        attribute: AttributeId,
        sampler: impl FnMut() -> Option<DataValue> + Send + 'static,
        sampling_interval: Duration,
        is_new: bool,
    ) {
        let mut samplers = self.samplers.lock();
        let id = (node_id, attribute);
        let sampler = samplers.entry(id).or_insert(SamplerItem {
            sampler: Box::new(sampler),
            sampling_interval,
            last_sample: Instant::now(),
            item_count: 0,
        });
        if is_new {
            sampler.item_count += 1;
        }
        if sampler.sampling_interval < sampling_interval && sampler.item_count == 1 {
            sampler.sampling_interval = sampling_interval;
        } else if sampler.sampling_interval > sampling_interval {
            sampler.sampling_interval = sampling_interval;
        }
    }

    pub fn remove_sampler(&self, node_id: NodeId, attribute: AttributeId) {
        let mut samplers = self.samplers.lock();
        let id = (node_id, attribute);

        let Some(sampler) = samplers.get_mut(&id) else {
            return;
        };
        if sampler.item_count > 0 {
            sampler.item_count -= 1;
        }
        if sampler.item_count == 0 {
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
