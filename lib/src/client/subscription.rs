// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! Provides subscription and monitored item tracking.
//!
//! The structs and functions in this file allow the client to maintain a shadow copy of the
//! subscription and monitored item state on the server. If the server goes down and the session
//! needs to be recreated, the client API can reconstruct the subscriptions and monitored item from
//! its shadow version.
//!
//! None of this is for public consumption. The client is expected to recreate state automatically
//! on a reconnect if necessary.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    marker::Sync,
    sync::Arc,
};

use crate::sync::*;
use crate::types::{
    service_types::{DataChangeNotification, ReadValueId},
    *,
};

use super::callbacks::OnSubscriptionNotification;

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
    // The thing that is actually being monitored - the node id, attribute, index, encoding.
    item_to_monitor: ReadValueId,
    /// Queue size
    queue_size: usize,
    /// Discard oldest
    discard_oldest: bool,
    /// Monitoring mode
    monitoring_mode: MonitoringMode,
    /// Sampling interval
    sampling_interval: f64,
    /// Last value of the item
    last_value: DataValue,
    /// A list of all values received in the last data change notification. This list is cleared immediately
    /// after the data change notification.
    values: Vec<DataValue>,
    /// Triggered items
    triggered_items: BTreeSet<u32>,
}

impl MonitoredItem {
    pub fn new(client_handle: u32) -> MonitoredItem {
        MonitoredItem {
            id: 0,
            queue_size: 1,
            sampling_interval: 0.0,
            item_to_monitor: ReadValueId {
                node_id: NodeId::null(),
                attribute_id: 0,
                index_range: UAString::null(),
                data_encoding: QualifiedName::null(),
            },
            monitoring_mode: MonitoringMode::Reporting,
            discard_oldest: false,
            last_value: DataValue::null(),
            values: Vec::with_capacity(1),
            client_handle,
            triggered_items: BTreeSet::new(),
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn client_handle(&self) -> u32 {
        self.client_handle
    }

    pub fn item_to_monitor(&self) -> &ReadValueId {
        &self.item_to_monitor
    }

    pub fn sampling_interval(&self) -> f64 {
        self.sampling_interval
    }

    pub fn queue_size(&self) -> usize {
        self.queue_size
    }

    pub fn last_value(&self) -> &DataValue {
        &self.last_value
    }

    pub fn values(&self) -> &Vec<DataValue> {
        &self.values
    }

    pub fn clear_values(&mut self) {
        self.values.clear();
    }

    pub fn append_new_value(&mut self, value: DataValue) {
        if self.values.len() == self.queue_size {
            let _ = self.values.pop();
            self.values.push(value);
        }
    }

    pub fn monitoring_mode(&self) -> MonitoringMode {
        self.monitoring_mode
    }

    pub fn discard_oldest(&self) -> bool {
        self.discard_oldest
    }

    pub(crate) fn set_id(&mut self, value: u32) {
        self.id = value;
    }

    pub(crate) fn set_item_to_monitor(&mut self, item_to_monitor: ReadValueId) {
        self.item_to_monitor = item_to_monitor;
    }

    pub(crate) fn set_sampling_interval(&mut self, value: f64) {
        self.sampling_interval = value;
    }

    pub(crate) fn set_queue_size(&mut self, value: usize) {
        self.queue_size = value;
        if self.queue_size > self.values.capacity() {
            self.values
                .reserve(self.queue_size - self.values.capacity());
        }
    }

    pub(crate) fn set_monitoring_mode(&mut self, monitoring_mode: MonitoringMode) {
        self.monitoring_mode = monitoring_mode;
    }

    pub(crate) fn set_discard_oldest(&mut self, discard_oldest: bool) {
        self.discard_oldest = discard_oldest;
    }

    pub(crate) fn set_triggering(&mut self, links_to_add: &[u32], links_to_remove: &[u32]) {
        links_to_remove.iter().for_each(|i| {
            self.triggered_items.remove(i);
        });
        links_to_add.iter().for_each(|i| {
            self.triggered_items.insert(*i);
        });
    }

    pub(crate) fn triggered_items(&self) -> &BTreeSet<u32> {
        &self.triggered_items
    }
}

pub struct Subscription {
    /// Subscription id, supplied by server
    subscription_id: u32,
    /// Publishing interval in seconds
    publishing_interval: f64,
    /// Lifetime count, revised by server
    lifetime_count: u32,
    /// Max keep alive count, revised by server
    max_keep_alive_count: u32,
    /// Max notifications per publish, revised by server
    max_notifications_per_publish: u32,
    /// Publishing enabled
    publishing_enabled: bool,
    /// Priority
    priority: u8,
    /// The change callback will be what is called if any monitored item changes within a cycle.
    /// The monitored item is referenced by its id
    notification_callback: Arc<Mutex<dyn OnSubscriptionNotification + Send + Sync>>,
    /// A map of monitored items associated with the subscription (key = monitored_item_id)
    monitored_items: HashMap<u32, MonitoredItem>,
    /// A map of client handle to monitored item id
    client_handles: HashMap<u32, u32>,
}

impl Subscription {
    /// Creates a new subscription using the supplied parameters and the supplied data change callback.
    pub fn new(
        subscription_id: u32,
        publishing_interval: f64,
        lifetime_count: u32,
        max_keep_alive_count: u32,
        max_notifications_per_publish: u32,
        publishing_enabled: bool,
        priority: u8,
        notification_callback: Arc<Mutex<dyn OnSubscriptionNotification + Send + Sync>>,
    ) -> Subscription {
        Subscription {
            subscription_id,
            publishing_interval,
            lifetime_count,
            max_keep_alive_count,
            max_notifications_per_publish,
            publishing_enabled,
            priority,
            notification_callback,
            monitored_items: HashMap::new(),
            client_handles: HashMap::new(),
        }
    }

    pub fn monitored_items(&self) -> &HashMap<u32, MonitoredItem> {
        &self.monitored_items
    }

    pub fn subscription_id(&self) -> u32 {
        self.subscription_id
    }

    pub fn publishing_interval(&self) -> f64 {
        self.publishing_interval
    }

    pub fn lifetime_count(&self) -> u32 {
        self.lifetime_count
    }

    pub fn max_keep_alive_count(&self) -> u32 {
        self.max_keep_alive_count
    }

    pub fn max_notifications_per_publish(&self) -> u32 {
        self.max_notifications_per_publish
    }

    pub fn publishing_enabled(&self) -> bool {
        self.publishing_enabled
    }

    pub fn priority(&self) -> u8 {
        self.priority
    }

    pub fn notification_callback(
        &self,
    ) -> Arc<Mutex<dyn OnSubscriptionNotification + Send + Sync>> {
        self.notification_callback.clone()
    }

    pub(crate) fn set_publishing_interval(&mut self, publishing_interval: f64) {
        self.publishing_interval = publishing_interval;
    }

    pub(crate) fn set_lifetime_count(&mut self, lifetime_count: u32) {
        self.lifetime_count = lifetime_count;
    }

    pub(crate) fn set_max_keep_alive_count(&mut self, max_keep_alive_count: u32) {
        self.max_keep_alive_count = max_keep_alive_count;
    }

    pub(crate) fn set_max_notifications_per_publish(&mut self, max_notifications_per_publish: u32) {
        self.max_notifications_per_publish = max_notifications_per_publish;
    }

    pub(crate) fn set_priority(&mut self, priority: u8) {
        self.priority = priority;
    }

    pub(crate) fn set_publishing_enabled(&mut self, publishing_enabled: bool) {
        self.publishing_enabled = publishing_enabled;
    }

    pub(crate) fn insert_monitored_items(&mut self, items_to_create: &[CreateMonitoredItem]) {
        items_to_create.iter().for_each(|i| {
            let mut monitored_item = MonitoredItem::new(i.client_handle);
            monitored_item.set_id(i.id);
            monitored_item.set_monitoring_mode(i.monitoring_mode);
            monitored_item.set_discard_oldest(i.discard_oldest);
            monitored_item.set_sampling_interval(i.sampling_interval);
            monitored_item.set_queue_size(i.queue_size as usize);
            monitored_item.set_item_to_monitor(i.item_to_monitor.clone());

            let client_handle = monitored_item.client_handle();
            let monitored_item_id = monitored_item.id();
            self.monitored_items
                .insert(monitored_item_id, monitored_item);
            self.client_handles.insert(client_handle, monitored_item_id);
        });
    }

    pub(crate) fn modify_monitored_items(&mut self, items_to_modify: &[ModifyMonitoredItem]) {
        items_to_modify.iter().for_each(|i| {
            if let Some(ref mut monitored_item) = self.monitored_items.get_mut(&i.id) {
                monitored_item.set_sampling_interval(i.sampling_interval);
                monitored_item.set_queue_size(i.queue_size as usize);
            }
        });
    }

    pub(crate) fn delete_monitored_items(&mut self, items_to_delete: &[u32]) {
        items_to_delete.iter().for_each(|id| {
            // Remove the monitored item and the client handle / id entry
            if let Some(monitored_item) = self.monitored_items.remove(id) {
                let _ = self.client_handles.remove(&monitored_item.client_handle());
            }
        })
    }

    pub(crate) fn set_triggering(
        &mut self,
        triggering_item_id: u32,
        links_to_add: &[u32],
        links_to_remove: &[u32],
    ) {
        if let Some(ref mut monitored_item) = self.monitored_items.get_mut(&triggering_item_id) {
            monitored_item.set_triggering(links_to_add, links_to_remove);
        }
    }

    fn monitored_item_id_from_handle(&self, client_handle: u32) -> Option<u32> {
        self.client_handles.get(&client_handle).copied()
    }

    pub(crate) fn on_event(&mut self, events: &[EventNotificationList]) {
        let mut cb = trace_lock!(self.notification_callback);
        events.iter().for_each(|event| {
            cb.on_event(event);
        });
    }

    pub(crate) fn on_data_change(&mut self, data_change_notifications: &[DataChangeNotification]) {
        let mut monitored_item_ids = HashSet::new();
        data_change_notifications.iter().for_each(|n| {
            if let Some(ref monitored_items) = n.monitored_items {
                monitored_item_ids.clear();
                for i in monitored_items {
                    let monitored_item_id = {
                        let monitored_item_id = self.monitored_item_id_from_handle(i.client_handle);
                        if monitored_item_id.is_none() {
                            continue;
                        }
                        *monitored_item_id.as_ref().unwrap()
                    };
                    let monitored_item = self.monitored_items.get_mut(&monitored_item_id).unwrap();
                    monitored_item.last_value = i.value.clone();
                    monitored_item.values.push(i.value.clone());
                    monitored_item_ids.insert(monitored_item_id);
                }
                if !monitored_item_ids.is_empty() {
                    let data_change_items: Vec<&MonitoredItem> = monitored_item_ids
                        .iter()
                        .map(|id| self.monitored_items.get(id).unwrap())
                        .collect();

                    {
                        // Call the call back with the changes we collected
                        let mut cb = trace_lock!(self.notification_callback);
                        cb.on_data_change(&data_change_items);
                    }

                    // Clear the values
                    monitored_item_ids.iter().for_each(|id| {
                        let m = self.monitored_items.get_mut(id).unwrap();
                        m.clear_values();
                    });
                }
            }
        });
    }
}
