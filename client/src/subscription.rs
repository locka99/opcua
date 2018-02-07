use opcua_types::*;
use std::collections::HashMap;

// This file will hold functionality related to creating a subscription and monitoring items

pub struct CreateMonitoredItem {
    pub id: UInt32,
    pub client_handle: UInt32,
    pub sampling_interval: Double,
    pub queue_size: UInt32,
}

pub struct ModifyMonitoredItem {
    pub id: UInt32,
    pub sampling_interval: Double,
    pub queue_size: UInt32,
}

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
    client_handle: UInt32,
}

impl MonitoredItem {
    pub fn new(client_handle: UInt32) -> MonitoredItem {
        MonitoredItem {
            id: 0,
            queue_size: 0,
            sampling_interval: 0.0,
            node_id: NodeId::null(),
            attribute_id: AttributeId::Value,
            index_range: None,
            value: DataValue::null(),
            client_handle,
        }
    }

    pub fn id(&self) -> UInt32 {
        self.id
    }

    pub fn set_id(&mut self, value: UInt32) {
        self.id = value;
    }

    pub fn client_handle(&self) -> UInt32 {
        self.client_handle
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

    pub fn value(&self) -> DataValue {
        self.value.clone()
    }

    pub fn set_value(&mut self, value: DataValue) {
        self.value = value
    }
}

pub struct Subscription {
    /// Subscription id, supplied by server
    subscription_id: UInt32,
    /// Publishing interval in seconds
    publishing_interval: Double,
    /// Lifetime count, revised by server
    lifetime_count: UInt32,
    /// Max keep alive count, revised by server
    max_keep_alive_count: UInt32,
    /// Max notifications per publish, revised by server
    max_notifications_per_publish: UInt32,
    /// Publishing enabled
    publishing_enabled: Boolean,
    /// Priority
    priority: Byte,
    /// The change callback will be what is called if any monitored item changes within a cycle.
    /// The monitored item is referenced by its id
    change_callback: Option<Box<FnOnce(&Vec<UInt32>) + Send + 'static>>,
    /// A map of monitored items associated with the subscription (key = monitored_item_id)
    monitored_items: HashMap<UInt32, MonitoredItem>,
    /// A map of client handle to monitored item id
    client_handles: HashMap<UInt32, UInt32>,
}

impl Subscription {
    pub fn new<F>(subscription_id: UInt32, publishing_interval: Double, lifetime_count: UInt32, max_keep_alive_count: UInt32, max_notifications_per_publish: UInt32, publishing_enabled: Boolean, priority: Byte, callback: F) -> Subscription
        where F: FnOnce(&Vec<UInt32>) + Send + 'static {
        Subscription {
            subscription_id,
            publishing_interval,
            lifetime_count,
            max_keep_alive_count,
            max_notifications_per_publish,
            publishing_enabled,
            priority,
            change_callback: Some(Box::new(callback)),
            monitored_items: HashMap::new(),
            client_handles: HashMap::new(),
        }
    }

    pub fn subscription_id(&self) -> UInt32 { self.subscription_id }

    pub fn publishing_interval(&self) -> Double { self.publishing_interval }

    pub fn set_publishing_interval(&mut self, publishing_interval: Double) { self.publishing_interval = publishing_interval; }

    pub fn lifetime_count(&self) -> UInt32 { self.lifetime_count }

    pub fn set_lifetime_count(&mut self, lifetime_count: UInt32) { self.lifetime_count = lifetime_count; }

    pub fn max_keep_alive_count(&self) -> UInt32 { self.max_keep_alive_count }

    pub fn set_max_keep_alive_count(&mut self, max_keep_alive_count: UInt32) { self.max_keep_alive_count = max_keep_alive_count; }

    pub fn max_notifications_per_publish(&self) -> UInt32 { self.max_notifications_per_publish }

    pub fn set_max_notifications_per_publish(&mut self, max_notifications_per_publish: UInt32) { self.max_notifications_per_publish = max_notifications_per_publish; }

    pub fn priority(&self) -> Byte { self.priority }

    pub fn set_priority(&mut self, priority: Byte) { self.priority = priority; }

    pub fn publishing_enabled(&self) -> Boolean { self.publishing_enabled }

    pub fn insert_monitored_items(&mut self, items_to_create: Vec<CreateMonitoredItem>) {
        items_to_create.iter().for_each(|i| {
            let mut monitored_item = MonitoredItem::new(i.client_handle);
            monitored_item.set_id(i.id);
            monitored_item.set_sampling_interval(i.sampling_interval);
            monitored_item.set_queue_size(i.queue_size);

            let client_handle = monitored_item.client_handle();
            let monitored_item_id = monitored_item.id();
            self.monitored_items.insert(monitored_item_id, monitored_item);
            self.client_handles.insert(client_handle, monitored_item_id);
        });
    }

    pub fn modify_monitored_items(&mut self, items_to_modify: Vec<ModifyMonitoredItem>) {
        items_to_modify.into_iter().for_each(|i| {
            if let Some(ref mut monitored_item) = self.monitored_items.get_mut(&i.id) {
                monitored_item.set_sampling_interval(i.sampling_interval);
                monitored_item.set_queue_size(i.queue_size);
            }
        });
    }

    pub fn delete_monitored_items(&mut self, items_to_delete: Vec<UInt32>) {
        items_to_delete.iter().for_each(|id| {
            // Remove the monitored item and the client handle / id entry
            if let Some(monitored_item) = self.monitored_items.remove(&id) {
                let _ = self.client_handles.remove(&monitored_item.client_handle());
            }
        })
    }
}