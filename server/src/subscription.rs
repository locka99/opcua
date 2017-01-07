use opcua_core::types::*;

use monitored_item::MonitoredItem;

pub struct Subscription {
    /// List of monitored items
    pub monitored_items: Vec<MonitoredItem>,

    pub requested_lifetime_count: UInt16,
    pub lifetime_count: UInt16,

    pub requested_keep_alive_count: UInt16,
    pub keep_alive_count: UInt16,

    /// Relative priority of the subscription. When more than
    /// one subscription needs to send notifications the highest
    /// priority subscription should be sent first.
    pub priority: Byte,
}

const DEFAULT_LIFETIME_COUNT: UInt16 = 30;
const DEFAULT_KEEP_ALIVE_COUNT: UInt16 = 10;

impl Subscription {
    pub fn new() -> Subscription {
        Subscription {
            monitored_items: Vec::new(),
            priority: 0,
            requested_lifetime_count: DEFAULT_LIFETIME_COUNT,
            lifetime_count: DEFAULT_LIFETIME_COUNT,
            requested_keep_alive_count: DEFAULT_KEEP_ALIVE_COUNT,
            keep_alive_count: DEFAULT_KEEP_ALIVE_COUNT,
        }
    }
}