use std::result::Result;

use chrono;
use time;

use opcua_core::types::*;

use address_space::*;

#[derive(Debug, Clone, PartialEq)]
pub enum FilterType {
    DataChangeFilter(DataChangeFilter)
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
    last_sample_time: chrono::DateTime<chrono::UTC>,
    last_data_value: Option<DataValue>,
    queue_overflow: bool,
}

impl MonitoredItem {
    pub fn new(monitored_item_id: UInt32, request: &MonitoredItemCreateRequest) -> Result<MonitoredItem, &'static StatusCode> {

        // Check if the filter is supported type
        if request.requested_parameters.filter.node_id != ObjectId::DataChangeFilter_Encoding_DefaultBinary.as_node_id() {
            return Err(&BAD_FILTER_NOT_ALLOWED);
        }

        let filter = FilterType::DataChangeFilter(request.requested_parameters.filter.decode_inner::<DataChangeFilter>()?);

        // TODO sampling interval and queue size should be revised
        let sampling_interval = request.requested_parameters.sampling_interval;
        let queue_size = if request.requested_parameters.queue_size < 1 { 1 } else { request.requested_parameters.queue_size as usize };

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
    pub fn tick(&mut self, address_space: &AddressSpace, now: &chrono::DateTime<chrono::UTC>, subscription_interval_elapsed: bool) -> bool {
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
            subscription_interval_elapsed
        } else {
            // Always check on the first tick
            self.last_data_value.is_none()
        };

        // Test the value (or don't)
        if !check_value {
            return false;
        }
        if let Some(node) = address_space.find_node(&self.item_to_monitor.node_id) {
            let node = node.as_node();
            let attribute_id = AttributeId::from_u32(self.item_to_monitor.attribute_id);
            if attribute_id.is_err() {
                return false;
            }
            let attribute_id = attribute_id.unwrap();

            let data_value = node.find_attribute(attribute_id);
            if let Some(data_value) = data_value {
                // Test for data change
                let data_change = if self.last_data_value.is_none() {
                    // There is no previous check so yes it changed
                    true
                }
                else {
                    // Test if the value has changed since the last test
                    let last_data_value = self.last_data_value.as_ref().unwrap();


                    // TODO for numeric types, look at the DataChangeFilter's deadband settings

                    data_value != *last_data_value
                };

                if data_change {
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
                        // Overflow behaviour
                        if self.discard_oldest {
                            // Throw away last item, push the rest up
                            let _ = self.notification_queue.pop();
                            self.notification_queue.insert(0, notification_message);
                        } else {
                            self.notification_queue[0] = notification_message;
                        }
                        self.queue_overflow = true;
                    } else {
                        self.notification_queue.insert(0, notification_message);
                    }
                }

                self.last_sample_time = now.clone();

                data_change
            } else {
                false
            }
        } else {
            false
        }
    }
}