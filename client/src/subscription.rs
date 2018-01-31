use std::collections::HashMap;

use opcua_types::*;

// This file will hold functionality related to creating a subscription and monitoring items

pub struct MonitoredItem {
    /// This is the monitored item's id within the subscription
    pub id: UInt32,
    /// Queue size
    pub queue_size: UInt32,
    /// Sampling interval
    pub sampling_interval: Double,
    /// Monitored item's node id
    pub node_id: NodeId,
    /// Attribute id to monitor
    pub attribute_id: AttributeId,
    /// Numeric range for array monitoring
    pub index_range: Option<NumericRange>,
    /// Last value of the item
    pub value: DataValue,
}

impl MonitoredItem {
    pub fn new() -> MonitoredItem {
        MonitoredItem {
            id: 0,
            queue_size: 0,
            sampling_interval: 0.0,
            node_id: NodeId::null(),
            attribute_id: AttributeId::Value,
            index_range: None,
            value: DataValue::null(),
        }
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
            monitored_items: HashMap::new(),
        }
    }
}