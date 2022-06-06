// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::collections::{BTreeSet, VecDeque};
use std::result::Result;

use crate::types::{
    node_ids::ObjectId,
    service_types::{
        DataChangeFilter, EventFieldList, EventFilter, MonitoredItemCreateRequest,
        MonitoredItemModifyRequest, MonitoredItemNotification, ReadValueId, TimestampsToReturn,
    },
    status_code::StatusCode,
    *,
};

use crate::server::{
    address_space::{node::Node, AddressSpace, EventNotifier},
    events::event_filter,
    state::ServerState,
};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Notification {
    MonitoredItemNotification(MonitoredItemNotification),
    Event(EventFieldList),
}

impl From<MonitoredItemNotification> for Notification {
    fn from(v: MonitoredItemNotification) -> Self {
        Notification::MonitoredItemNotification(v)
    }
}

impl From<EventFieldList> for Notification {
    fn from(v: EventFieldList) -> Self {
        Notification::Event(v)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) enum FilterType {
    None,
    DataChangeFilter(DataChangeFilter),
    EventFilter(EventFilter),
}

impl FilterType {
    pub fn from_filter(
        filter: &ExtensionObject,
        decoding_options: &DecodingOptions,
    ) -> Result<FilterType, StatusCode> {
        // Check if the filter is a supported filter type
        let filter_type_id = &filter.node_id;
        if filter_type_id.is_null() {
            // No data filter was passed, so just a dumb value comparison
            Ok(FilterType::None)
        } else if let Ok(filter_type_id) = filter_type_id.as_object_id() {
            match filter_type_id {
                ObjectId::DataChangeFilter_Encoding_DefaultBinary => {
                    Ok(FilterType::DataChangeFilter(
                        filter.decode_inner::<DataChangeFilter>(decoding_options)?,
                    ))
                }
                ObjectId::EventFilter_Encoding_DefaultBinary => Ok(FilterType::EventFilter(
                    filter.decode_inner::<EventFilter>(decoding_options)?,
                )),
                _ => {
                    error!(
                        "Requested data filter type is not supported, {:?}",
                        filter_type_id
                    );
                    Err(StatusCode::BadFilterNotAllowed)
                }
            }
        } else {
            error!(
                "Requested data filter type is not an object id, {:?}",
                filter_type_id
            );
            Err(StatusCode::BadFilterNotAllowed)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct MonitoredItem {
    monitored_item_id: u32,
    item_to_monitor: ReadValueId,
    monitoring_mode: MonitoringMode,
    // Triggered items are other monitored items in the same subscription which are reported if this
    // monitored item changes.
    triggered_items: BTreeSet<u32>,
    client_handle: u32,
    sampling_interval: Duration,
    filter: FilterType,
    discard_oldest: bool,
    queue_size: usize,
    /// The notification queue is arranged from oldest to newest, i.e. pop front gets the oldest
    /// message, pop back gets the most recent.
    notification_queue: VecDeque<Notification>,
    queue_overflow: bool,
    timestamps_to_return: TimestampsToReturn,
    last_sample_time: DateTimeUtc,
    last_data_value: Option<DataValue>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TickResult {
    /// The value changed and it should be reported
    ReportValueChanged,
    /// The value changed and it should not be reported (sampling)
    ValueChanged,
    /// The value did not change
    NoChange,
}

impl MonitoredItem {
    pub fn new(
        now: &DateTimeUtc,
        monitored_item_id: u32,
        timestamps_to_return: TimestampsToReturn,
        server_state: &ServerState,
        request: &MonitoredItemCreateRequest,
    ) -> Result<MonitoredItem, StatusCode> {
        let filter = FilterType::from_filter(
            &request.requested_parameters.filter,
            &server_state.decoding_options(),
        )?;
        let sampling_interval = Self::sanitize_sampling_interval(
            server_state,
            request.requested_parameters.sampling_interval,
        );
        let queue_size = Self::sanitize_queue_size(
            server_state,
            request.requested_parameters.queue_size as usize,
        );
        Ok(MonitoredItem {
            monitored_item_id,
            item_to_monitor: request.item_to_monitor.clone(),
            monitoring_mode: request.monitoring_mode,
            triggered_items: BTreeSet::new(),
            client_handle: request.requested_parameters.client_handle,
            sampling_interval,
            filter,
            discard_oldest: request.requested_parameters.discard_oldest,
            timestamps_to_return,
            last_sample_time: *now,
            last_data_value: None,
            queue_size,
            notification_queue: VecDeque::with_capacity(queue_size),
            queue_overflow: false,
        })
    }

    /// Modifies the existing item with the values of the modify request. On success, the result
    /// holds the filter result.
    pub fn modify(
        &mut self,
        server_state: &ServerState,
        address_space: &AddressSpace,
        timestamps_to_return: TimestampsToReturn,
        request: &MonitoredItemModifyRequest,
    ) -> Result<ExtensionObject, StatusCode> {
        self.timestamps_to_return = timestamps_to_return;
        self.filter = FilterType::from_filter(
            &request.requested_parameters.filter,
            &server_state.decoding_options(),
        )?;
        self.sampling_interval = Self::sanitize_sampling_interval(
            server_state,
            request.requested_parameters.sampling_interval,
        );
        self.queue_size = Self::sanitize_queue_size(
            server_state,
            request.requested_parameters.queue_size as usize,
        );
        self.client_handle = request.requested_parameters.client_handle;
        self.discard_oldest = request.requested_parameters.discard_oldest;

        // Shrink / grow the notification queue to the new threshold
        if self.notification_queue.len() > self.queue_size {
            // Discard old notifications
            let discard = self.queue_size - self.notification_queue.len();
            let _ = self.notification_queue.drain(0..discard);
            // TODO potential edge case with discard oldest behaviour
            // Shrink the queue
            self.notification_queue.shrink_to_fit();
        } else if self.notification_queue.capacity() < self.queue_size {
            // Reserve space for more elements
            let extra_capacity = self.queue_size - self.notification_queue.capacity();
            self.notification_queue.reserve(extra_capacity);
        }
        // Validate the filter, return that from this function
        self.validate_filter(address_space)
    }

    /// Adds or removes other monitored items which will be triggered when this monitored item changes
    pub fn set_triggering(&mut self, items_to_add: &[u32], items_to_remove: &[u32]) {
        // Spec says to process remove items before adding new ones.
        items_to_remove.iter().for_each(|i| {
            self.triggered_items.remove(i);
        });
        items_to_add.iter().for_each(|i| {
            self.triggered_items.insert(*i);
        });
    }

    /// Validates the filter associated with the monitored item and returns the filter result
    /// encoded in an extension object.
    pub fn validate_filter(
        &self,
        address_space: &AddressSpace,
    ) -> Result<ExtensionObject, StatusCode> {
        // Event filter must be validated
        let filter_result = if let FilterType::EventFilter(ref event_filter) = self.filter {
            let filter_result = event_filter::validate(event_filter, address_space)?;
            ExtensionObject::from_encodable(
                ObjectId::EventFilterResult_Encoding_DefaultBinary,
                &filter_result,
            )
        } else {
            // DataChangeFilter has no result
            ExtensionObject::null()
        };
        Ok(filter_result)
    }

    /// Called repeatedly on the monitored item.
    ///
    /// If the monitored item has a negative interval and subscription interval has elapsed,
    /// the value is tested immediately. Otherwise, the monitored items sampling interval is enforced
    /// the subscriptions and controls the rate.
    ///
    /// Function returns a `TickResult` denoting if the value changed or not, and whether it should
    /// be reported.
    pub fn tick(
        &mut self,
        now: &DateTimeUtc,
        address_space: &AddressSpace,
        publishing_interval_elapsed: bool,
        resend_data: bool,
    ) -> TickResult {
        if self.monitoring_mode == MonitoringMode::Disabled {
            TickResult::NoChange
        } else {
            let check_value = if resend_data {
                // Always check for resend_data flag
                true
            } else if self.sampling_interval < 0f64 {
                // -1 means use the subscription publishing interval so if the publishing interval elapsed,
                // then this monitored item is evaluated otherwise it won't be.
                publishing_interval_elapsed
            } else if self.sampling_interval == 0f64 {
                // 0 means fastest practical rate, i.e. the tick quantum itself
                // 0 is also used for clients subscribing for events.
                true
            } else {
                // Compare sample interval to the time elapsed
                let sampling_interval = super::duration_from_ms(self.sampling_interval);
                let elapsed = now.signed_duration_since(self.last_sample_time);
                elapsed >= sampling_interval
            };

            // Test the value (or don't)
            let value_changed = check_value && {
                // Indicate a change if reporting is enabled
                let first_tick = !self.is_event_filter() && self.last_data_value.is_none();
                let value_changed = self.check_value(address_space, now, resend_data);
                first_tick || value_changed || !self.notification_queue.is_empty()
            };

            if value_changed {
                if self.monitoring_mode == MonitoringMode::Reporting {
                    TickResult::ReportValueChanged
                } else {
                    TickResult::ValueChanged
                }
            } else {
                TickResult::NoChange
            }
        }
    }

    /// Gets the event notifier bits for a node, or empty if there are no bits
    fn get_event_notifier(node: &dyn Node) -> EventNotifier {
        if let Some(v) = node.get_attribute(
            TimestampsToReturn::Neither,
            AttributeId::EventNotifier,
            NumericRange::None,
            &QualifiedName::null(),
        ) {
            if let Variant::Byte(v) = v.value.unwrap_or_else(|| 0u8.into()) {
                EventNotifier::from_bits_truncate(v)
            } else {
                EventNotifier::empty()
            }
        } else {
            EventNotifier::empty()
        }
    }

    /// Check for
    fn check_for_events(
        &mut self,
        address_space: &AddressSpace,
        happened_since: &DateTimeUtc,
        node: &dyn Node,
    ) -> bool {
        match self.filter {
            FilterType::EventFilter(ref filter) => {
                // Node has to allow subscribe to events
                if Self::get_event_notifier(node).contains(EventNotifier::SUBSCRIBE_TO_EVENTS) {
                    let object_id = node.node_id();
                    if let Some(events) = event_filter::evaluate(
                        &object_id,
                        filter,
                        address_space,
                        happened_since,
                        self.client_handle,
                    ) {
                        events
                            .into_iter()
                            .for_each(|event| self.enqueue_notification_message(event));
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => panic!(),
        }
    }

    fn check_for_data_change(
        &mut self,
        _address_space: &AddressSpace,
        resend_data: bool,
        attribute_id: AttributeId,
        node: &dyn Node,
    ) -> bool {
        let data_value = node.get_attribute(
            TimestampsToReturn::Neither,
            attribute_id,
            NumericRange::None,
            &QualifiedName::null(),
        );
        if let Some(mut data_value) = data_value {
            // Test for data change
            let data_change = if resend_data {
                true
            } else if let Some(ref last_data_value) = self.last_data_value {
                // If there is a filter on the monitored item then the filter determines
                // if the value is considered to have changed, otherwise it is a straight
                // equality test.
                match self.filter {
                    FilterType::None => data_value.value != last_data_value.value,
                    FilterType::DataChangeFilter(ref filter) => {
                        !filter.compare(&data_value, last_data_value, None)
                    }
                    _ => {
                        // Unrecognized filter
                        false
                    }
                }
            } else {
                // There is no previous data value so yes consider it changed
                trace!(
                    "No last data value so item has changed, node {:?}",
                    self.item_to_monitor.node_id
                );
                true
            };
            if data_change {
                trace!(
                    "Data change on item -, node {:?}, data_value = {:?}",
                    self.item_to_monitor.node_id,
                    data_value
                );

                // Store current data value to compare against on the next tick
                self.last_data_value = Some(data_value.clone());

                // Strip out timestamps that subscriber is not interested in
                match self.timestamps_to_return {
                    TimestampsToReturn::Neither | TimestampsToReturn::Invalid => {
                        data_value.source_timestamp = None;
                        data_value.source_picoseconds = None;
                        data_value.server_timestamp = None;
                        data_value.server_picoseconds = None
                    }
                    TimestampsToReturn::Server => {
                        data_value.source_timestamp = None;
                        data_value.source_picoseconds = None;
                    }
                    TimestampsToReturn::Source => {
                        data_value.server_timestamp = None;
                        data_value.server_picoseconds = None
                    }
                    TimestampsToReturn::Both => {
                        // DO NOTHING
                    }
                }

                // Enqueue notification message
                let client_handle = self.client_handle;
                self.enqueue_notification_message(MonitoredItemNotification {
                    client_handle,
                    value: data_value,
                });

                trace!("Monitored item state = {:?}", self);
            } else {
                trace!(
                    "No data change on item, node {:?}",
                    self.item_to_monitor.node_id
                );
            }
            data_change
        } else {
            false
        }
    }

    fn is_event_filter(&self) -> bool {
        matches!(self.filter, FilterType::EventFilter(_))
    }

    /// Fetches the most recent value of the monitored item from the source and compares
    /// it to the last value. If the value has changed according to a filter / equality
    /// check, the latest value and its timestamps will be stored in the monitored item.
    ///
    /// The function will return true if the value was changed, false otherwise.
    pub fn check_value(
        &mut self,
        address_space: &AddressSpace,
        now: &DateTimeUtc,
        resend_data: bool,
    ) -> bool {
        if self.monitoring_mode == MonitoringMode::Disabled {
            panic!("Should not check value while monitoring mode is disabled");
        }
        let changed = if let Some(node) = address_space.find_node(&self.item_to_monitor.node_id) {
            match AttributeId::from_u32(self.item_to_monitor.attribute_id) {
                Ok(attribute_id) => {
                    let node = node.as_node();
                    match self.filter {
                        FilterType::EventFilter(_) => {
                            // EventFilter is only relevant on the EventNotifier attribute
                            if attribute_id == AttributeId::EventNotifier {
                                let happened_since = self.last_sample_time;
                                self.check_for_events(address_space, &happened_since, node)
                            } else {
                                false
                            }
                        }
                        _ => self.check_for_data_change(
                            address_space,
                            resend_data,
                            attribute_id,
                            node,
                        ),
                    }
                }
                Err(_) => {
                    trace!(
                        "Item has no attribute_id {} so it hasn't changed, node {:?}",
                        self.item_to_monitor.attribute_id,
                        self.item_to_monitor.node_id
                    );
                    false
                }
            }
        } else {
            trace!(
                "Cannot find item to monitor, node {:?}",
                self.item_to_monitor.node_id
            );
            false
        };
        self.last_sample_time = *now;
        changed
    }

    /// Enqueues a notification message for the monitored item
    pub fn enqueue_notification_message<T>(&mut self, notification: T)
    where
        T: Into<Notification>,
    {
        // test for overflow
        let overflow = if self.notification_queue.len() == self.queue_size {
            trace!(
                "Data change overflow, node {:?}",
                self.item_to_monitor.node_id
            );
            // Overflow behaviour
            if self.discard_oldest {
                // Throw away oldest item (the one at the start) to make space at the end
                let _ = self.notification_queue.pop_front();
            } else {
                // Remove the latest notification
                self.notification_queue.pop_back();
            }
            // Overflow only affects queues > 1 element
            self.queue_size > 1
        } else {
            false
        };
        let mut notification = notification.into();
        if overflow {
            if let Notification::MonitoredItemNotification(ref mut notification) = notification {
                // Set the overflow bit on the data value's status
                notification.value.status =
                    Some(notification.value.status() | StatusCode::OVERFLOW);
            }
            self.queue_overflow = true;
        }
        self.notification_queue.push_back(notification);
    }

    /// Gets the oldest notification message from the notification queue
    #[cfg(test)]
    pub fn oldest_notification_message(&mut self) -> Option<Notification> {
        if self.notification_queue.is_empty() {
            None
        } else {
            self.queue_overflow = false;
            self.notification_queue.pop_front()
        }
    }

    /// Retrieves all the notification messages from the queue, oldest to newest
    pub fn all_notifications(&mut self) -> Option<Vec<Notification>> {
        if self.notification_queue.is_empty() {
            None
        } else {
            // Removes all the queued notifications to the output
            self.queue_overflow = false;
            Some(self.notification_queue.drain(..).collect())
        }
    }

    /// Takes the requested sampling interval value supplied by client and ensures it is within
    /// the range supported by the server
    fn sanitize_sampling_interval(
        server_state: &ServerState,
        requested_sampling_interval: f64,
    ) -> f64 {
        if requested_sampling_interval < 0.0 {
            // From spec "any negative number is interpreted as -1"
            // -1 means monitored item's sampling interval defaults to the subscription's publishing interval
            -1.0
        } else if requested_sampling_interval == 0.0
            || requested_sampling_interval < server_state.min_sampling_interval_ms
        {
            server_state.min_sampling_interval_ms
        } else {
            requested_sampling_interval
        }
    }

    /// Takes the requested queue size and ensures it is within the range supported by the server
    fn sanitize_queue_size(server_state: &ServerState, requested_queue_size: usize) -> usize {
        if requested_queue_size == 0 || requested_queue_size == 1 {
            // For data monitored items 0 -> 1
            // Future - for event monitored items, queue size should be the default queue size for event notifications
            1
        // Future - for event monitored items, the minimum queue size the server requires for event notifications
        } else if requested_queue_size > server_state.max_monitored_item_queue_size {
            server_state.max_monitored_item_queue_size
        // Future - for event monitored items MaxUInt32 returns the maximum queue size the server support
        // for event notifications
        } else {
            requested_queue_size
        }
    }

    pub fn monitored_item_id(&self) -> u32 {
        self.monitored_item_id
    }

    pub fn client_handle(&self) -> u32 {
        self.client_handle
    }

    pub fn sampling_interval(&self) -> Duration {
        self.sampling_interval
    }

    pub fn triggered_items(&self) -> &BTreeSet<u32> {
        &self.triggered_items
    }

    pub fn set_monitoring_mode(&mut self, monitoring_mode: MonitoringMode) {
        self.monitoring_mode = monitoring_mode;
    }

    pub fn monitoring_mode(&self) -> MonitoringMode {
        self.monitoring_mode
    }

    pub fn queue_size(&self) -> usize {
        self.queue_size
    }

    #[cfg(test)]
    pub fn queue_overflow(&self) -> bool {
        self.queue_overflow
    }

    #[cfg(test)]
    pub fn notification_queue(&self) -> &VecDeque<Notification> {
        &self.notification_queue
    }

    #[cfg(test)]
    pub(crate) fn set_discard_oldest(&mut self, discard_oldest: bool) {
        self.discard_oldest = discard_oldest;
    }
}
