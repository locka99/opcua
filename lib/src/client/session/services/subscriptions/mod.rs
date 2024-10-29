pub mod event_loop;
pub use event_loop::SubscriptionActivity;

mod service;
pub mod state;

use std::{
    collections::{BTreeSet, HashMap},
    time::Duration,
};

use crate::types::{
    DataChangeNotification, DataValue, DecodingOptions, EventNotificationList, ExtensionObject,
    Identifier, MonitoringMode, NotificationMessage, ObjectId, ReadValueId,
    StatusChangeNotification, Variant,
};

pub(crate) struct CreateMonitoredItem {
    pub id: u32,
    pub client_handle: u32,
    pub item_to_monitor: ReadValueId,
    pub monitoring_mode: MonitoringMode,
    pub queue_size: u32,
    pub discard_oldest: bool,
    pub sampling_interval: f64,
    pub filter: ExtensionObject,
}

pub(crate) struct ModifyMonitoredItem {
    pub id: u32,
    pub sampling_interval: f64,
    pub queue_size: u32,
}

/// A set of callbacks for notifications on a subscription.
/// You may implement this on your own struct, or simply use [SubscriptionCallbacks]
/// for a simple collection of closures.
pub trait OnSubscriptionNotification: Send + Sync {
    /// Called when a subscription changes state on the server.
    fn on_subscription_status_change(&mut self, _notification: StatusChangeNotification) {}

    /// Called for each data value change.
    fn on_data_value(&mut self, _notification: DataValue, _item: &MonitoredItem) {}

    /// Called for each received event.
    fn on_event(&mut self, _event_fields: Option<Vec<Variant>>, _item: &MonitoredItem) {}
}

/// A convenient wrapper around a set of callback functions that implements [OnSubscriptionNotification]
pub struct SubscriptionCallbacks {
    status_change: Box<dyn FnMut(StatusChangeNotification) + Send + Sync>,
    data_value: Box<dyn FnMut(DataValue, &MonitoredItem) + Send + Sync>,
    event: Box<dyn FnMut(Option<Vec<Variant>>, &MonitoredItem) + Send + Sync>,
}

impl SubscriptionCallbacks {
    /// Create a new subscription callback wrapper.
    ///
    /// # Arguments
    ///
    /// * `status_change` - Called when a subscription changes state on the server.
    /// * `data_value` - Called for each received data value.
    /// * `event` - Called for each received event.
    pub fn new(
        status_change: impl FnMut(StatusChangeNotification) + Send + Sync + 'static,
        data_value: impl FnMut(DataValue, &MonitoredItem) + Send + Sync + 'static,
        event: impl FnMut(Option<Vec<Variant>>, &MonitoredItem) + Send + Sync + 'static,
    ) -> Self {
        Self {
            status_change: Box::new(status_change)
                as Box<dyn FnMut(StatusChangeNotification) + Send + Sync>,
            data_value: Box::new(data_value)
                as Box<dyn FnMut(DataValue, &MonitoredItem) + Send + Sync>,
            event: Box::new(event)
                as Box<dyn FnMut(Option<Vec<Variant>>, &MonitoredItem) + Send + Sync>,
        }
    }
}

impl OnSubscriptionNotification for SubscriptionCallbacks {
    fn on_subscription_status_change(&mut self, notification: StatusChangeNotification) {
        (&mut self.status_change)(notification);
    }

    fn on_data_value(&mut self, notification: DataValue, item: &MonitoredItem) {
        (&mut self.data_value)(notification, item);
    }

    fn on_event(&mut self, event_fields: Option<Vec<Variant>>, item: &MonitoredItem) {
        (&mut self.event)(event_fields, item);
    }
}

/// A wrapper around a data change callback that implements [OnSubscriptionNotification]
pub struct DataChangeCallback {
    data_value: Box<dyn FnMut(DataValue, &MonitoredItem) + Send + Sync>,
}

impl DataChangeCallback {
    /// Create a new data change callback wrapper.
    ///
    /// # Arguments
    ///
    /// * `data_value` - Called for each received data value.
    pub fn new(data_value: impl FnMut(DataValue, &MonitoredItem) + Send + Sync + 'static) -> Self {
        Self {
            data_value: Box::new(data_value)
                as Box<dyn FnMut(DataValue, &MonitoredItem) + Send + Sync>,
        }
    }
}

impl OnSubscriptionNotification for DataChangeCallback {
    fn on_data_value(&mut self, notification: DataValue, item: &MonitoredItem) {
        (&mut self.data_value)(notification, item);
    }
}

/// A wrapper around an event callback that implements [OnSubscriptionNotification]
pub struct EventCallback {
    event: Box<dyn FnMut(Option<Vec<Variant>>, &MonitoredItem) + Send + Sync>,
}

impl EventCallback {
    /// Create a new event callback wrapper.
    ///
    /// # Arguments
    ///
    /// * `data_value` - Called for each received data value.
    pub fn new(
        event: impl FnMut(Option<Vec<Variant>>, &MonitoredItem) + Send + Sync + 'static,
    ) -> Self {
        Self {
            event: Box::new(event)
                as Box<dyn FnMut(Option<Vec<Variant>>, &MonitoredItem) + Send + Sync>,
        }
    }
}

impl OnSubscriptionNotification for EventCallback {
    fn on_event(&mut self, event_fields: Option<Vec<Variant>>, item: &MonitoredItem) {
        (&mut self.event)(event_fields, item);
    }
}

pub struct MonitoredItem {
    /// This is the monitored item's id within the subscription
    id: u32,
    /// Monitored item's handle. Used internally - not modifiable
    client_handle: u32,
    // The thing that is actually being monitored - the node id, attribute, index, encoding.
    item_to_monitor: ReadValueId,
    /// Queue size
    queue_size: usize,
    /// Monitoring mode
    monitoring_mode: MonitoringMode,
    /// Sampling interval
    sampling_interval: f64,
    /// Triggered items
    triggered_items: BTreeSet<u32>,
    /// Whether to discard oldest values on queue overflow
    discard_oldest: bool,
    /// Active filter
    filter: ExtensionObject,
}

impl MonitoredItem {
    pub fn new(client_handle: u32) -> MonitoredItem {
        MonitoredItem {
            id: 0,
            client_handle,
            item_to_monitor: ReadValueId::default(),
            queue_size: 1,
            monitoring_mode: MonitoringMode::Reporting,
            sampling_interval: 0.0,
            triggered_items: BTreeSet::new(),
            discard_oldest: true,
            filter: ExtensionObject::null(),
        }
    }

    /// Server assigned ID of the monitored item.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Client assigned handle for the monitored item.
    pub fn client_handle(&self) -> u32 {
        self.client_handle
    }

    /// Attribute and node ID for the item the monitored item receives notifications for.
    pub fn item_to_monitor(&self) -> &ReadValueId {
        &self.item_to_monitor
    }

    /// Sampling interval.
    pub fn sampling_interval(&self) -> f64 {
        self.sampling_interval
    }

    /// Queue size on the server.
    pub fn queue_size(&self) -> usize {
        self.queue_size
    }

    /// Whether the oldest values are discarded on queue overflow on the server.
    pub fn discard_oldest(&self) -> bool {
        self.discard_oldest
    }

    pub(crate) fn set_sampling_interval(&mut self, value: f64) {
        self.sampling_interval = value;
    }

    pub(crate) fn set_queue_size(&mut self, value: usize) {
        self.queue_size = value;
    }

    pub(crate) fn set_monitoring_mode(&mut self, monitoring_mode: MonitoringMode) {
        self.monitoring_mode = monitoring_mode;
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
    publishing_interval: Duration,
    /// Lifetime count, revised by server
    lifetime_count: u32,
    /// Max keep alive count, revised by server
    max_keep_alive_count: u32,
    /// Max notifications per publish, revised by server
    max_notifications_per_publish: u32,
    /// Publishing enabled
    publishing_enabled: bool,
    /// Subscription priority
    priority: u8,

    /// A map of monitored items associated with the subscription (key = monitored_item_id)
    monitored_items: HashMap<u32, MonitoredItem>,
    /// A map of client handle to monitored item id
    client_handles: HashMap<u32, u32>,

    callback: Box<dyn OnSubscriptionNotification>,
}

impl Subscription {
    /// Creates a new subscription using the supplied parameters and the supplied data change callback.
    pub fn new(
        subscription_id: u32,
        publishing_interval: Duration,
        lifetime_count: u32,
        max_keep_alive_count: u32,
        max_notifications_per_publish: u32,
        priority: u8,
        publishing_enabled: bool,
        status_change_callback: Box<dyn OnSubscriptionNotification>,
    ) -> Subscription {
        Subscription {
            subscription_id,
            publishing_interval,
            lifetime_count,
            max_keep_alive_count,
            max_notifications_per_publish,
            publishing_enabled,
            priority,
            monitored_items: HashMap::new(),
            client_handles: HashMap::new(),
            callback: status_change_callback,
        }
    }

    pub fn monitored_items(&self) -> &HashMap<u32, MonitoredItem> {
        &self.monitored_items
    }

    pub fn subscription_id(&self) -> u32 {
        self.subscription_id
    }

    pub fn publishing_interval(&self) -> Duration {
        self.publishing_interval
    }

    pub fn lifetime_count(&self) -> u32 {
        self.lifetime_count
    }

    pub fn priority(&self) -> u8 {
        self.priority
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

    pub(crate) fn set_publishing_interval(&mut self, publishing_interval: Duration) {
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

    pub(crate) fn set_publishing_enabled(&mut self, publishing_enabled: bool) {
        self.publishing_enabled = publishing_enabled;
    }

    pub(crate) fn set_priority(&mut self, priority: u8) {
        self.priority = priority;
    }

    pub(crate) fn insert_monitored_items(&mut self, items_to_create: Vec<CreateMonitoredItem>) {
        items_to_create.into_iter().for_each(|i| {
            let monitored_item = MonitoredItem {
                id: i.id,
                client_handle: i.client_handle,
                item_to_monitor: i.item_to_monitor,
                queue_size: i.queue_size as usize,
                monitoring_mode: i.monitoring_mode,
                sampling_interval: i.sampling_interval,
                triggered_items: BTreeSet::new(),
                discard_oldest: i.discard_oldest,
                filter: i.filter,
            };

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

    pub(crate) fn on_notification(
        &mut self,
        notification: NotificationMessage,
        decoding_options: &DecodingOptions,
    ) {
        let Some(notifications) = notification.notification_data else {
            return;
        };

        for obj in notifications {
            if obj.node_id.namespace != 0 {
                continue;
            }

            let Identifier::Numeric(id) = obj.node_id.identifier else {
                continue;
            };

            if id == ObjectId::DataChangeNotification_Encoding_DefaultBinary as u32 {
                match obj.decode_inner::<DataChangeNotification>(decoding_options) {
                    Ok(it) => {
                        for notif in it.monitored_items.into_iter().flatten() {
                            let item = self
                                .client_handles
                                .get(&notif.client_handle)
                                .and_then(|handle| self.monitored_items.get(handle));

                            if let Some(item) = item {
                                self.callback.on_data_value(notif.value, item);
                            }
                        }
                    }
                    Err(e) => warn!("Failed to decode data change notification: {e}"),
                }
            } else if id == ObjectId::EventNotificationList_Encoding_DefaultBinary as u32 {
                match obj.decode_inner::<EventNotificationList>(decoding_options) {
                    Ok(it) => {
                        for notif in it.events.into_iter().flatten() {
                            let item = self
                                .client_handles
                                .get(&notif.client_handle)
                                .and_then(|handle| self.monitored_items.get(handle));

                            if let Some(item) = item {
                                self.callback.on_event(notif.event_fields, item);
                            }
                        }
                    }
                    Err(e) => warn!("Failed to decode event notification: {e}"),
                }
            } else if id == ObjectId::StatusChangeNotification_Encoding_DefaultBinary as u32 {
                match obj.decode_inner::<StatusChangeNotification>(decoding_options) {
                    Ok(it) => self.callback.on_subscription_status_change(it),
                    Err(e) => warn!("Failed to decode status change notification: {e}"),
                }
            }
        }
    }
}
