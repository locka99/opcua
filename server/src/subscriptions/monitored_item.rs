use std::result::Result;

use chrono;
use time;

use opcua_core::types::*;

use constants;

use DateTimeUTC;
use address_space::*;

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
        } else if filter_type_id == &ObjectId::DataChangeFilter_Encoding_DefaultBinary.as_node_id() {
            Ok(FilterType::DataChangeFilter(filter.decode_inner::<DataChangeFilter>()?))
        } else {
            error!("Requested data filter type is not supported, {:?}", filter_type_id);
            Err(BAD_FILTER_NOT_ALLOWED)
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
    last_sample_time: DateTimeUTC,
    last_data_value: Option<DataValue>,
    queue_overflow: bool,
}

impl MonitoredItem {
    pub fn new(monitored_item_id: UInt32, request: &MonitoredItemCreateRequest) -> Result<MonitoredItem, StatusCode> {
        let filter = FilterType::from_filter(&request.requested_parameters.filter)?;
        let sampling_interval = MonitoredItem::sanitize_sampling_interval(request.requested_parameters.sampling_interval);
        let queue_size = MonitoredItem::sanitize_queue_size(request.requested_parameters.queue_size as usize);
        Ok(MonitoredItem {
            monitored_item_id: monitored_item_id,
            item_to_monitor: request.item_to_monitor.clone(),
            monitoring_mode: request.monitoring_mode,
            client_handle: request.requested_parameters.client_handle,
            sampling_interval: sampling_interval,
            filter: filter,
            discard_oldest: request.requested_parameters.discard_oldest,
            last_sample_time: chrono::UTC::now(),
            last_data_value: None,
            queue_size: queue_size,
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

    /// Gets the oldest notification message from the notification queue
    pub fn get_notification_message(&mut self) -> Option<MonitoredItemNotification> {
        if self.notification_queue.is_empty() {
            None
        } else {
            // Take first item off the queue
            self.queue_overflow = false;
            Some(self.notification_queue.remove(0))
        }
    }

    /// Called repeatedly on the monitored item.
    ///
    /// If the monitored item has a negative interval and subscription interval has elapsed,
    /// the value is tested immediately. Otherwise, the monitored items sampling interval is enforced
    /// the subscriptions and controls the rate.
    ///
    /// Function returns true if a notification message was added to the queue
    pub fn tick(&mut self, address_space: &AddressSpace, now: &DateTimeUTC, publishing_timer_expired: bool) -> bool {
        let check_value = if self.sampling_interval > 0f64 {
            // Compare sample interval
            let sampling_interval = time::Duration::milliseconds(self.sampling_interval as i64);
            let elapsed = *now - self.last_sample_time;
            elapsed >= sampling_interval
        } else if self.sampling_interval == 0f64 {
            // Fastest possible rate, i.e. tick quantum
            true
        } else if self.sampling_interval < 0f64 {
            // If the subscription interval elapsed, then this monitored item is evaluated
            publishing_timer_expired
        } else {
            // Always check on the first tick
            self.last_data_value.is_none()
        };

        // Test the value (or don't)
        if !check_value {
            return false;
        }

        self.last_sample_time = now.clone();

        if let Some(node) = address_space.find_node(&self.item_to_monitor.node_id) {
            let node = node.as_node();
            let attribute_id = AttributeId::from_u32(self.item_to_monitor.attribute_id);
            if attribute_id.is_err() {
                debug!("Item has no attribute_id {:?} so it hasn't changed, node {:?}", attribute_id, self.item_to_monitor.node_id);
                return false;
            }
            let attribute_id = attribute_id.unwrap();
            let data_value = node.find_attribute(attribute_id);
            if let Some(data_value) = data_value {
                // Test for data change
                let data_change = if self.last_data_value.is_none() {
                    // There is no previous check so yes it changed
                    debug!("No last data value so item has changed, node {:?}", self.item_to_monitor.node_id);
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
                    debug!("Data change on item -, node {:?}, data_value = {:?}", self.item_to_monitor.node_id, data_value);

                    // Store data value for comparison purposes - perhaps a dirty flag could achieve
                    // this more efficiently
                    self.last_data_value = Some(data_value.clone());

                    // Data change
                    let notification_message = MonitoredItemNotification {
                        client_handle: self.client_handle,
                        value: data_value,
                    };

                    // enqueue notification
                    // NB it would be more efficient but more complex to make the last item of the vec,
                    // the most recent and the first, the least recent.
                    if self.notification_queue.len() == self.queue_size {
                        debug!("Data change overflow, node {:?}", self.item_to_monitor.node_id);
                        // Overflow behaviour
                        if self.discard_oldest {
                            // Throw away oldest item (the one at the start), push the rest up
                            let _ = self.notification_queue.remove(0);
                        } else {
                            // Replace the last notification
                            self.notification_queue.pop();
                        }
                        self.notification_queue.push(notification_message);
                        self.queue_overflow = true;
                    } else {
                        self.notification_queue.push(notification_message);
                    }

                    debug!("Monitored item state = {:?}", self);
                } else {
                    debug!("No data change on item, node {:?}", self.item_to_monitor.node_id);
                }
                data_change
            } else {
                false
            }
        } else {
            debug!("Can't find item to monitor, node {:?}", self.item_to_monitor.node_id);
            false
        }
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