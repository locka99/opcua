use std::result::Result;
use std::collections::VecDeque;

use chrono;

use opcua_types::*;
use opcua_types::status_code::StatusCode;
use opcua_types::node_ids::ObjectId;
use opcua_types::service_types::{TimestampsToReturn, DataChangeFilter, ReadValueId, MonitoredItemCreateRequest, MonitoredItemModifyRequest, MonitoredItemNotification};

use constants;

use DateTimeUtc;
use address_space::AddressSpace;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum FilterType {
    None,
    DataChangeFilter(DataChangeFilter),
}

impl FilterType {
    pub fn from_filter(filter: &ExtensionObject) -> Result<FilterType, StatusCode> {
        // Check if the filter is a supported filter type
        let filter_type_id = &filter.node_id;
        if filter_type_id.is_null() {
            // No data filter was passed, so just a dumb value comparison
            Ok(FilterType::None)
        } else if filter_type_id == &ObjectId::DataChangeFilter_Encoding_DefaultBinary.into() {
            let decoding_limits = DecodingLimits::default(); // TODO
            Ok(FilterType::DataChangeFilter(filter.decode_inner::<DataChangeFilter>(&decoding_limits)?))
        } else {
            error!("Requested data filter type is not supported, {:?}", filter_type_id);
            Err(StatusCode::BadFilterNotAllowed)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MonitoredItem {
    pub monitored_item_id: UInt32,
    pub item_to_monitor: ReadValueId,
    pub monitoring_mode: MonitoringMode,
    pub client_handle: UInt32,
    pub sampling_interval: Duration,
    pub filter: FilterType,
    pub discard_oldest: Boolean,
    pub queue_size: usize,
    /// The notification queue is arranged from oldest to newest, i.e. pop front gets the oldest
    /// message, pop back gets the most recent.
    pub notification_queue: VecDeque<MonitoredItemNotification>,
    pub queue_overflow: bool,
    timestamps_to_return: TimestampsToReturn,
    last_sample_time: DateTimeUtc,
    last_data_value: Option<DataValue>,
}

impl MonitoredItem {
    pub fn new(monitored_item_id: UInt32, timestamps_to_return: TimestampsToReturn, request: &MonitoredItemCreateRequest) -> Result<MonitoredItem, StatusCode> {
        let filter = FilterType::from_filter(&request.requested_parameters.filter)?;
        let sampling_interval = Self::sanitize_sampling_interval(request.requested_parameters.sampling_interval);
        let queue_size = Self::sanitize_queue_size(request.requested_parameters.queue_size as usize);
        Ok(MonitoredItem {
            monitored_item_id,
            item_to_monitor: request.item_to_monitor.clone(),
            monitoring_mode: request.monitoring_mode,
            client_handle: request.requested_parameters.client_handle,
            sampling_interval,
            filter,
            discard_oldest: request.requested_parameters.discard_oldest,
            timestamps_to_return,
            last_sample_time: chrono::Utc::now(),
            last_data_value: None,
            queue_size,
            notification_queue: VecDeque::with_capacity(queue_size),
            queue_overflow: false,
        })
    }

    /// Modifies the existing item with the values of the modify request
    pub fn modify(&mut self, timestamps_to_return: TimestampsToReturn, request: &MonitoredItemModifyRequest) -> Result<(), StatusCode> {
        self.timestamps_to_return = timestamps_to_return;
        self.filter = FilterType::from_filter(&request.requested_parameters.filter)?;
        self.sampling_interval = Self::sanitize_sampling_interval(request.requested_parameters.sampling_interval);
        self.queue_size = Self::sanitize_queue_size(request.requested_parameters.queue_size as usize);
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

        Ok(())
    }

    /// Called repeatedly on the monitored item.
    ///
    /// If the monitored item has a negative interval and subscription interval has elapsed,
    /// the value is tested immediately. Otherwise, the monitored items sampling interval is enforced
    /// the subscriptions and controls the rate.
    ///
    /// Function returns true if a notification message was created and should be reported.
    pub fn tick(&mut self, address_space: &AddressSpace, now: &DateTimeUtc, publishing_interval_elapsed: bool) -> bool {
        if self.monitoring_mode == MonitoringMode::Disabled {
            false
        } else {
            let check_value = if self.last_data_value.is_none() {
                // Always check on the first tick
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
            if check_value {
                // Indicate a change if reporting is enabled
                let value_has_changed = self.check_value(address_space, now) && self.monitoring_mode == MonitoringMode::Reporting;
                // println!("Monitored item using its own interval changed = {}", value_has_changed);
                value_has_changed
            } else {
                false
            }
        }
    }

    /// Fetches the most recent value of the monitored item from the source and compares
    /// it to the last value. If the value has changed according to a filter / equality
    /// check, the latest value and its timestamps will be stored in the monitored item.
    ///
    /// The function will return true if the value was changed, false otherwise.
    fn check_value(&mut self, address_space: &AddressSpace, now: &DateTimeUtc) -> bool {
        self.last_sample_time = *now;
        if let Some(node) = address_space.find_node(&self.item_to_monitor.node_id) {
            let node = node.as_node();
            let attribute_id = AttributeId::from_u32(self.item_to_monitor.attribute_id);
            if attribute_id.is_err() {
                trace!("Item has no attribute_id {:?} so it hasn't changed, node {:?}", attribute_id, self.item_to_monitor.node_id);
                return false;
            }
            let attribute_id = attribute_id.unwrap();
            let data_value = node.find_attribute(attribute_id);
            if let Some(mut data_value) = data_value {
                // Test for data change
                let data_change = if let Some(ref last_data_value) = self.last_data_value {
                    // If there is a filter on the monitored item then the filter determines
                    // if the value is considered to have changed, otherwise it is a straight
                    // equality test.
                    if let FilterType::DataChangeFilter(ref filter) = self.filter {
                        !filter.compare(&data_value, last_data_value, None)
                    } else {
                        data_value.value != last_data_value.value
                    }
                } else {
                    // There is no previous data value so yes consider it changed
                    trace!("No last data value so item has changed, node {:?}", self.item_to_monitor.node_id);
                    true
                };
                if data_change {
                    trace!("Data change on item -, node {:?}, data_value = {:?}", self.item_to_monitor.node_id, data_value);

                    // Store current data value to compare against on the next tick
                    self.last_data_value = Some(data_value.clone());

                    // Strip out timestamps that subscriber is not interested in
                    match self.timestamps_to_return {
                        TimestampsToReturn::Neither => {
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
                        _ => {}
                    }

                    // Enqueue notification message
                    let client_handle = self.client_handle;
                    self.enqueue_notification_message(MonitoredItemNotification {
                        client_handle,
                        value: data_value,
                    });

                    trace!("Monitored item state = {:?}", self);
                } else {
                    trace!("No data change on item, node {:?}", self.item_to_monitor.node_id);
                }
                data_change
            } else {
                false
            }
        } else {
            trace!("Can't find item to monitor, node {:?}", self.item_to_monitor.node_id);
            false
        }
    }

    /// Enqueues a notification message for the monitored item
    pub fn enqueue_notification_message(&mut self, mut notification: MonitoredItemNotification) {
        // test for overflow
        let overflow = if self.notification_queue.len() == self.queue_size {
            trace!("Data change overflow, node {:?}", self.item_to_monitor.node_id);
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
        if overflow {
            // Set the overflow bit on the data value's status
            let mut status_code = notification.value.status();
            status_code = status_code | StatusCode::OVERFLOW.bits();
            notification.value.status = Some(status_code);
            self.queue_overflow = true;
        }
        self.notification_queue.push_back(notification);
    }

    /// Gets the oldest notification message from the notification queue
    pub fn oldest_notification_message(&mut self) -> Option<MonitoredItemNotification> {
        if self.notification_queue.is_empty() {
            None
        } else {
            // Take first item off the queue
            self.queue_overflow = false;
            self.notification_queue.pop_front()
        }
    }

    /// Gets the last notification (and discards the remainder to prevent out of sequence events) from
    /// the notification queue.
    pub fn latest_notification_message(&mut self) -> Option<MonitoredItemNotification> {
        let result = self.notification_queue.pop_back();
        if result.is_some() {
            self.queue_overflow = false;
            self.notification_queue.clear();
        }
        result
    }

    /// Retrieves all the notification messages from the queue, oldest to newest
    pub fn all_notification_messages(&mut self) -> Option<Vec<MonitoredItemNotification>> {
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
    fn sanitize_sampling_interval(requested_sampling_interval: Double) -> Double {
        if requested_sampling_interval < 0.0 {
            // From spec "any negative number is interpreted as -1"
            // -1 means monitored item's sampling interval defaults to the subscription's publishing interval
            -1.0
        } else if requested_sampling_interval == 0.0 || requested_sampling_interval < constants::MIN_SAMPLING_INTERVAL {
            constants::MIN_SAMPLING_INTERVAL
        } else {
            requested_sampling_interval
        }
    }

    /// Takes the requested queue size and ensures it is within the range supported by the server
    fn sanitize_queue_size(requested_queue_size: usize) -> usize {
        if requested_queue_size == 0 {
            // For data monitored items 0 -> 1
            1
            // Future - for event monitored items, queue size should be the default queue size for event notifications
        } else if requested_queue_size == 1 {
            1
            // Future - for event monitored items, the minimum queue size the server requires for event notifications
        } else if requested_queue_size > constants::MAX_DATA_CHANGE_QUEUE_SIZE {
            constants::MAX_DATA_CHANGE_QUEUE_SIZE
            // Future - for event monitored items MaxUInt32 returns the maximum queue size the server support
            // for event notifications
        } else {
            requested_queue_size
        }
    }
}