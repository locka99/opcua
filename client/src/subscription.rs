use std::collections::HashMap;

use opcua_types::*;

// This file will hold functionality related to creating a subscription and monitoring items

pub struct MonitoredItem {
    /// This is the monitored item's id within the subscription
    id: UInt32,
    /// Queue size
    queue_size: UInt32,
    /// Sampling interval
    sampling_interval: Double,
    /// Monitored item's node id
    node_id: NodeId,
    /// Attribute id to monitor
    attribute_id: AttributeId,
    /// Numeric range for array monitoring
    index_range: Option<NumericRange>,
    /// Last value of the item
    value: DataValue,
    /// Monitored item's handle. Used internally - not modifiable
    handle: UInt32,
}

impl MonitoredItem {
    pub fn new(handle: UInt32) -> MonitoredItem {
        MonitoredItem {
            id: 0,
            queue_size: 0,
            sampling_interval: 0.0,
            node_id: NodeId::null(),
            attribute_id: AttributeId::Value,
            index_range: None,
            value: DataValue::null(),
            handle,
        }
    }

    pub fn id(&self) -> UInt32 {
        self.id
    }

    pub fn set_id(&mut self, value: UInt32) {
        self.id = value;
    }

    pub fn handle(&self) -> UInt32 {
        self.handle
    }

    pub fn sampling_interval(&self) -> Double {
        self.sampling_interval
    }

    pub fn set_sampling_interval(&mut self, value: Double) {
        self.sampling_interval = value;
    }


    pub fn queue_size(&self) -> UInt32 {
        self.queue_size
    }

    pub fn set_queue_size(&mut self, value: UInt32) {
        self.queue_size = value;
    }
}

pub struct Subscription {
    pub subscription_id: UInt32,
    pub publishing_interval: Double,
    pub lifetime_count: UInt32,
    pub max_keep_alive_count: UInt32,
    pub max_notifications_per_publish: UInt32,
    pub publishing_enabled: Boolean,
    pub priority: Byte,
    /// The change callback will be what is called if any monitored item changes within a cycle.
    /// The monitored item is referenced by its id
    pub change_callback: Option<Box<FnOnce(&Vec<UInt32>) + Send + 'static>>,
    /// A list of monitored items associated with the subscription
    pub monitored_items: HashMap<UInt32, MonitoredItem>,
}

impl Subscription {
    pub fn new() -> Subscription {
        Subscription {
            subscription_id: 0,
            publishing_interval: 0f64,
            lifetime_count: 0,
            max_keep_alive_count: 0,
            max_notifications_per_publish: 0,
            publishing_enabled: true,
            priority: 0,
            change_callback: None,
            monitored_items: HashMap::new(),
        }
    }
}