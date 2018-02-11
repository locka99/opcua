use opcua_types::*;
use opcua_types::service_types::{DataChangeNotification, ReadValueId};
use std::collections::{HashMap, HashSet};

// This file will hold functionality related to creating a subscription and monitoring items

pub struct CreateMonitoredItem {
    pub id: UInt32,
    pub client_handle: UInt32,
    pub item_to_monitor: ReadValueId,
    pub queue_size: UInt32,
    pub sampling_interval: Double,
}

pub struct ModifyMonitoredItem {
    pub id: UInt32,
    pub sampling_interval: Double,
    pub queue_size: UInt32,
}

#[derive(Debug)]
pub struct MonitoredItem {
    /// This is the monitored item's id within the subscription
    id: UInt32,
    /// Monitored item's handle. Used internally - not modifiable
    client_handle: UInt32,
    // Item to monitor
    item_to_monitor: ReadValueId,
    /// Queue size
    queue_size: UInt32,
    /// Sampling interval
    sampling_interval: Double,
    /// Last value of the item
    value: DataValue,
}

impl MonitoredItem {
    pub fn new(client_handle: UInt32) -> MonitoredItem {
        MonitoredItem {
            id: 0,
            queue_size: 0,
            sampling_interval: 0.0,
            item_to_monitor: ReadValueId {
                node_id: NodeId::null(),
                attribute_id: 0,
                index_range: UAString::null(),
                data_encoding: QualifiedName::null(),
            },
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

    pub fn item_to_monitor(&self) -> ReadValueId { self.item_to_monitor.clone() }

    pub fn set_item_to_monitor(&mut self, item_to_monitor: ReadValueId) { self.item_to_monitor = item_to_monitor; }

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
}

/// This is the data cjamhe callback that clients register to receive item change notifications
pub struct DataChangeCallback {
    cb: Box<Fn(Vec<&MonitoredItem>) + Send + 'static>
}

impl DataChangeCallback {
    pub fn new<CB>(cb: CB) -> DataChangeCallback where CB: Fn(Vec<&MonitoredItem>) + Send + 'static {
        DataChangeCallback {
            cb: Box::new(cb)
        }
    }

    pub fn call(&self, data_change_items: Vec<&MonitoredItem>) {
        (self.cb)(data_change_items);
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
    data_change_callback: Option<DataChangeCallback>,
    /// A map of monitored items associated with the subscription (key = monitored_item_id)
    monitored_items: HashMap<UInt32, MonitoredItem>,
    /// A map of client handle to monitored item id
    client_handles: HashMap<UInt32, UInt32>,
}

impl Subscription {
    pub fn new(subscription_id: UInt32, publishing_interval: Double, lifetime_count: UInt32, max_keep_alive_count: UInt32, max_notifications_per_publish: UInt32, publishing_enabled: Boolean, priority: Byte, data_change_callback: DataChangeCallback) -> Subscription {
        Subscription {
            subscription_id,
            publishing_interval,
            lifetime_count,
            max_keep_alive_count,
            max_notifications_per_publish,
            publishing_enabled,
            priority,
            data_change_callback: Some(data_change_callback),
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
            monitored_item.set_item_to_monitor(i.item_to_monitor.clone());

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

    fn monitored_item_id_from_handle(&self, client_handle: UInt32) -> Option<UInt32> {
        if let Some(monitored_item_id) = self.client_handles.get(&client_handle) {
            Some(*monitored_item_id)
        } else {
            None
        }
    }

    pub fn data_change(&mut self, data_change_notifications: Vec<DataChangeNotification>) {
        let mut monitored_item_ids = HashSet::new();
        for n in data_change_notifications {
            if let Some(monitored_items) = n.monitored_items {
                for i in monitored_items {
                    let monitored_item_id = {
                        let monitored_item_id = self.monitored_item_id_from_handle(i.client_handle);
                        if monitored_item_id.is_none() {
                            continue;
                        }
                        *monitored_item_id.as_ref().unwrap()
                    };

                    let monitored_item = self.monitored_items.get_mut(&monitored_item_id).unwrap();
                    monitored_item.value = i.value;
                    monitored_item_ids.insert(monitored_item_id);
                }
            }
        }

        if !monitored_item_ids.is_empty() && self.data_change_callback.is_some() {
            let data_change_items: Vec<&MonitoredItem> = monitored_item_ids.iter()
                .map(|id| self.monitored_items.get(&id).unwrap()).collect();
            // Call the call back with the changes we collected
            self.data_change_callback.as_ref().unwrap().call(data_change_items);
        }
    }
}