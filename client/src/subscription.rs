//! Provides subscription and monitored item tracking.
//!
//! The structs and functions in this file allow the client to maintain a shadow copy of the
//! subscription and monitored item state on the server. If the server goes down and the session
//! needs to be recreated, the client API can reconstruct the subscriptions and monitored item from
//! its shadow version.
//!
//! None of this is for public consumption. The client is expected to recreate state automatically
//! on a reconnect if necessary.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::marker::Sync;

use opcua_types::*;
use opcua_types::service_types::{DataChangeNotification, ReadValueId};

use callbacks::OnDataChange;

pub(crate) struct CreateMonitoredItem {
    pub id: u32,
    pub client_handle: u32,
    pub item_to_monitor: ReadValueId,
    pub monitoring_mode: MonitoringMode,
    pub queue_size: u32,
    pub discard_oldest: bool,
    pub sampling_interval: f64,
}

pub(crate) struct ModifyMonitoredItem {
    pub id: u32,
    pub sampling_interval: f64,
    pub queue_size: u32,
}

#[derive(Debug)]
pub struct MonitoredItem {
    /// This is the monitored item's id within the subscription
    id: u32,
    /// Monitored item's handle. Used internally - not modifiable
    client_handle: u32,
    // Item to monitor
    item_to_monitor: ReadValueId,
    /// Queue size
    queue_size: u32,
    /// Discard oldest
    discard_oldest: bool,
    /// Monitoring mode
    monitoring_mode: MonitoringMode,
    /// Sampling interval
    sampling_interval: f64,
    /// Last value of the item
    value: DataValue,
}

impl MonitoredItem {
    pub fn new(client_handle: u32) -> MonitoredItem {
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
            monitoring_mode: MonitoringMode::Reporting,
            discard_oldest: false,
            value: DataValue::null(),
            client_handle,
        }
    }

    pub fn id(&self) -> u32 { self.id }

    pub fn set_id(&mut self, value: u32) {
        self.id = value;
    }

    pub fn client_handle(&self) -> u32 {
        self.client_handle
    }

    pub fn item_to_monitor(&self) -> ReadValueId { self.item_to_monitor.clone() }

    pub fn set_item_to_monitor(&mut self, item_to_monitor: ReadValueId) {
        self.item_to_monitor = item_to_monitor;
    }

    pub fn sampling_interval(&self) -> f64 { self.sampling_interval }

    pub fn set_sampling_interval(&mut self, value: f64) {
        self.sampling_interval = value;
    }

    pub fn queue_size(&self) -> u32 { self.queue_size }

    pub fn set_queue_size(&mut self, value: u32) {
        self.queue_size = value;
    }

    pub fn value(&self) -> DataValue {
        self.value.clone()
    }

    pub fn monitoring_mode(&self) -> MonitoringMode { self.monitoring_mode }

    pub fn set_monitoring_mode(&mut self, monitoring_mode: MonitoringMode) {
        self.monitoring_mode = monitoring_mode;
    }

    pub fn discard_oldest(&self) -> bool { self.discard_oldest }

    pub fn set_discard_oldest(&mut self, discard_oldest: bool) {
        self.discard_oldest = discard_oldest;
    }
}

pub(crate) struct Subscription {
    /// Subscription id, supplied by server
    pub subscription_id: u32,
    /// Publishing interval in seconds
    pub publishing_interval: f64,
    /// Lifetime count, revised by server
    pub lifetime_count: u32,
    /// Max keep alive count, revised by server
    pub max_keep_alive_count: u32,
    /// Max notifications per publish, revised by server
    pub max_notifications_per_publish: u32,
    /// Publishing enabled
    pub publishing_enabled: bool,
    /// Priority
    pub priority: u8,
    /// The change callback will be what is called if any monitored item changes within a cycle.
    /// The monitored item is referenced by its id
    pub data_change_callback: Arc<Mutex<OnDataChange + Send + Sync + 'static>>,
    /// A map of monitored items associated with the subscription (key = monitored_item_id)
    pub monitored_items: HashMap<u32, MonitoredItem>,
    /// A map of client handle to monitored item id
    pub client_handles: HashMap<u32, u32>,
}

impl Subscription {
    /// Creates a new subscription using the supplied parameters and the supplied data change callback.
    pub fn new(subscription_id: u32, publishing_interval: f64, lifetime_count: u32, max_keep_alive_count: u32, max_notifications_per_publish: u32,
               publishing_enabled: bool, priority: u8, data_change_callback: Arc<Mutex<dyn OnDataChange + Send + Sync + 'static>>)
               -> Subscription
    {
        Subscription {
            subscription_id,
            publishing_interval,
            lifetime_count,
            max_keep_alive_count,
            max_notifications_per_publish,
            publishing_enabled,
            priority,
            data_change_callback,
            monitored_items: HashMap::new(),
            client_handles: HashMap::new(),
        }
    }

    pub fn monitored_items(&self) -> &HashMap<u32, MonitoredItem> { &self.monitored_items }

    pub fn subscription_id(&self) -> u32 { self.subscription_id }

    pub fn publishing_interval(&self) -> f64 { self.publishing_interval }

    pub fn set_publishing_interval(&mut self, publishing_interval: f64) { self.publishing_interval = publishing_interval; }

    pub fn set_lifetime_count(&mut self, lifetime_count: u32) { self.lifetime_count = lifetime_count; }

    pub fn set_max_keep_alive_count(&mut self, max_keep_alive_count: u32) { self.max_keep_alive_count = max_keep_alive_count; }

    pub fn set_max_notifications_per_publish(&mut self, max_notifications_per_publish: u32) { self.max_notifications_per_publish = max_notifications_per_publish; }

    pub fn set_priority(&mut self, priority: u8) { self.priority = priority; }

    pub fn set_publishing_enabled(&mut self, publishing_enabled: bool) { self.publishing_enabled = publishing_enabled; }

    pub fn insert_monitored_items(&mut self, items_to_create: &[CreateMonitoredItem]) {
        items_to_create.iter().for_each(|i| {
            let mut monitored_item = MonitoredItem::new(i.client_handle);
            monitored_item.set_id(i.id);
            monitored_item.set_monitoring_mode(i.monitoring_mode);
            monitored_item.set_discard_oldest(i.discard_oldest);
            monitored_item.set_sampling_interval(i.sampling_interval);
            monitored_item.set_queue_size(i.queue_size);
            monitored_item.set_item_to_monitor(i.item_to_monitor.clone());

            let client_handle = monitored_item.client_handle();
            let monitored_item_id = monitored_item.id();
            self.monitored_items.insert(monitored_item_id, monitored_item);
            self.client_handles.insert(client_handle, monitored_item_id);
        });
    }

    pub fn modify_monitored_items(&mut self, items_to_modify: &[ModifyMonitoredItem]) {
        items_to_modify.into_iter().for_each(|i| {
            if let Some(ref mut monitored_item) = self.monitored_items.get_mut(&i.id) {
                monitored_item.set_sampling_interval(i.sampling_interval);
                monitored_item.set_queue_size(i.queue_size);
            }
        });
    }

    pub fn delete_monitored_items(&mut self, items_to_delete: &[u32]) {
        items_to_delete.iter().for_each(|id| {
            // Remove the monitored item and the client handle / id entry
            if let Some(monitored_item) = self.monitored_items.remove(&id) {
                let _ = self.client_handles.remove(&monitored_item.client_handle());
            }
        })
    }

    fn monitored_item_id_from_handle(&self, client_handle: u32) -> Option<u32> {
        if let Some(monitored_item_id) = self.client_handles.get(&client_handle) {
            Some(*monitored_item_id)
        } else {
            None
        }
    }

    pub fn data_change(&mut self, data_change_notifications: &[DataChangeNotification]) {
        let mut monitored_item_ids = HashSet::new();
        for n in data_change_notifications {
            if let Some(ref monitored_items) = n.monitored_items {
                for i in monitored_items {
                    let monitored_item_id = {
                        let monitored_item_id = self.monitored_item_id_from_handle(i.client_handle);
                        if monitored_item_id.is_none() {
                            continue;
                        }
                        *monitored_item_id.as_ref().unwrap()
                    };

                    let monitored_item = self.monitored_items.get_mut(&monitored_item_id).unwrap();
                    monitored_item.value = i.value.clone();
                    monitored_item_ids.insert(monitored_item_id);
                }
            }
        }

        if !monitored_item_ids.is_empty() {
            let data_change_items: Vec<&MonitoredItem> = monitored_item_ids.iter()
                .map(|id| self.monitored_items.get(&id).unwrap()).collect();

            // Call the call back with the changes we collected
            let mut cb = trace_lock_unwrap!(self.data_change_callback);
            cb.data_change(data_change_items);
        }
    }
}