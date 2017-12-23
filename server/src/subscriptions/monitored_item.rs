use std::result::Result;

use chrono;
use time;

use opcua_types::*;
use opcua_types::status_codes::StatusCode::*;

use constants;

use DateTimeUtc;
use address_space::address_space::AddressSpace;
use subscriptions::subscription::TickReason;

#[derive(Debug, Clone, PartialEq)]
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
            Ok(FilterType::DataChangeFilter(filter.decode_inner::<DataChangeFilter>()?))
        } else {
            error!("Requested data filter type is not supported, {:?}", filter_type_id);
            Err(BadFilterNotAllowed)
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MonitoredItem {
    pub monitored_item_id: UInt32,
    pub item_to_monitor: ReadValueId,
    pub monitoring_mode: MonitoringMode,
    pub client_handle: UInt32,
    pub sampling_interval: Duration,
    pub filter: FilterType,
    pub discard_oldest: Boolean,
    pub queue_size: usize,
    pub notification_queue: Vec<MonitoredItemNotification>,
    pub queue_overflow: bool,
    last_sample_time: DateTimeUtc,
    last_data_value: Option<DataValue>,
}

impl MonitoredItem {
    pub fn new(monitored_item_id: UInt32, request: &MonitoredItemCreateRequest) -> Result<MonitoredItem, StatusCode> {
        let filter = FilterType::from_filter(&request.requested_parameters.filter)?;
        let sampling_interval = MonitoredItem::sanitize_sampling_interval(request.requested_parameters.sampling_interval);
        let queue_size = MonitoredItem::sanitize_queue_size(request.requested_parameters.queue_size as usize);
        Ok(MonitoredItem {
            monitored_item_id,
            item_to_monitor: request.item_to_monitor.clone(),
            monitoring_mode: request.monitoring_mode,
            client_handle: request.requested_parameters.client_handle,
            sampling_interval,
            filter,
            discard_oldest: request.requested_parameters.discard_oldest,
            last_sample_time: chrono::Utc::now(),
            last_data_value: None,
            queue_size,
            notification_queue: Vec::with_capacity(queue_size),
            queue_overflow: false
        })
    }

    /// Modifies the existing item with the values of the modify request
    pub fn modify(&mut self, request: &MonitoredItemModifyRequest) -> Result<(), StatusCode> {
        self.filter = FilterType::from_filter(&request.requested_parameters.filter)?;
        self.sampling_interval = MonitoredItem::sanitize_sampling_interval(request.requested_parameters.sampling_interval);
        self.queue_size = MonitoredItem::sanitize_queue_size(request.requested_parameters.queue_size as usize);
        self.client_handle = request.requested_parameters.client_handle;
        self.discard_oldest = request.requested_parameters.discard_oldest;
        Ok(())
    }

    /// Called repeatedly on the monitored item.
    ///
    /// If the monitored item has a negative interval and subscription interval has elapsed,
    /// the value is tested immediately. Otherwise, the monitored items sampling interval is enforced
    /// the subscriptions and controls the rate.
    ///
    /// Function returns true if a notification message was added to the queue
    pub fn tick(&mut self, address_space: &AddressSpace, now: &DateTimeUtc, reason: TickReason) -> bool {
        let check_value = if self.sampling_interval > 0f64 {
            // Compare sample interval
            let sampling_interval = time::Duration::milliseconds(self.sampling_interval as i64);
            let elapsed = (*now).signed_duration_since(self.last_sample_time);
            elapsed >= sampling_interval
        } else if self.sampling_interval == 0f64 {
            // Fastest possible rate, i.e. tick quantum
            true
        } else if self.sampling_interval < 0f64 {
            // If the subscription interval elapsed, then this monitored item is evaluated
            reason == TickReason::TickTimerFired
        } else {
            // Always check on the first tick
            self.last_data_value.is_none()
        };

        // Test the value (or don't)
        if !check_value {
            return false;
        }

        // Test if monitoring
        if self.monitoring_mode == MonitoringMode::Disabled {
            return false;
        }

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
            if let Some(data_value) = data_value {
                // Test for data change
                let data_change = if self.last_data_value.is_none() {
                    // There is no previous check so yes it changed
                    trace!("No last data value so item has changed, node {:?}", self.item_to_monitor.node_id);
                    true
                } else {
                    match self.filter {
                        FilterType::None => {
                            data_value.value != self.last_data_value.as_ref().unwrap().value
                        }
                        FilterType::DataChangeFilter(ref filter) => {
                            // Use filter to compare values
                            !filter.compare(&data_value, self.last_data_value.as_ref().unwrap(), None)
                        }
                    }
                };
                if data_change {
                    trace!("Data change on item -, node {:?}, data_value = {:?}", self.item_to_monitor.node_id, data_value);

                    // Store current data value to compare against on the next tick
                    self.last_data_value = Some(data_value.clone());

                    // Enqueue notification message
                    let client_handle = self.client_handle;
                    self.enqueue_notification_message(MonitoredItemNotification {
                        client_handle: client_handle,
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
    pub fn enqueue_notification_message(&mut self, notification: MonitoredItemNotification) {
        // test for overflow
        self.queue_overflow = if self.notification_queue.len() == self.queue_size {
            trace!("Data change overflow, node {:?}", self.item_to_monitor.node_id);
            // Overflow behaviour
            if self.discard_oldest {
                // Throw away oldest item (the one at the start) to make space at the end
                let _ = self.notification_queue.remove(0);
            } else {
                // Remove the last notification
                self.notification_queue.pop();
            }
            // Overflow only affects queues > 1 element
            self.queue_size > 1
        } else {
            false
        };
        // Add to end
        self.notification_queue.push(notification);
    }

    /// Gets the oldest notification message from the notification queue
    pub fn remove_first_notification_message(&mut self) -> Option<MonitoredItemNotification> {
        if self.notification_queue.is_empty() {
            None
        } else {
            // Take first item off the queue
            self.queue_overflow = false;
            Some(self.notification_queue.remove(0))
        }
    }

    /// Gets all the notification messages from the queue
    pub fn remove_all_notification_messages(&mut self) -> Option<Vec<MonitoredItemNotification>> {
        if self.notification_queue.is_empty() {
            None
        } else {
            // Removes all the queued notifications to the output
            self.queue_overflow = false;
            Some(self.notification_queue.drain(..).collect())
        }
    }

    /// Gets the last notification (and discards the remainder to prevent out of sequence events) from
    /// the notification queue.
    pub fn remove_last_notification_message(&mut self) -> Option<MonitoredItemNotification> {
        let result = self.notification_queue.pop();
        if result.is_some() {
            self.queue_overflow = false;
            self.notification_queue.clear();
        }
        result
    }

    /// Takes the requested sampling interval value supplied by client and ensures it is within
    /// the range supported by the server
    fn sanitize_sampling_interval(requested_sampling_interval: Double) -> Double {
        if requested_sampling_interval < 0.0 {
            // Defaults to the subscription's publishing interval
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
            constants::DEFAULT_DATA_CHANGE_QUEUE_SIZE
        } else if requested_queue_size == 1 {
            constants::MIN_DATA_CHANGE_QUEUE_SIZE
        } else if requested_queue_size > constants::MAX_DATA_CHANGE_QUEUE_SIZE {
            constants::MAX_DATA_CHANGE_QUEUE_SIZE
        } else {
            requested_queue_size
        }
    }
}