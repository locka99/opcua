use opcua_types::*;

// This file will hold functionality related to creating a subscription and monitoring items

struct MonitoredItem {
    /// This is the monitored item's id within the subscription
    id: UInt32,
    /// Monitored item's node id
    node_id: NodeId,
    /// Attribute id to monitor
    attribute_id: UInt32,
    /// Numeric range for array monitoring
    index_range: NumericRange,
}

struct Subscription {
    /// A list of monitored items associated with the subscription
    monitored_items: Vec<UInt32>,
}