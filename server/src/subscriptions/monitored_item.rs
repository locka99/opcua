use chrono;
use time;

use opcua_core::types::*;

#[derive(Debug, Clone, PartialEq)]
pub struct MonitoredItem {
    pub monitored_item_id: UInt32,
    pub item_to_monitor: ReadValueId,
    pub monitoring_mode: MonitoringMode,
    pub client_handle: UInt32,
    pub sampling_interval: Duration,
    pub filter: ExtensionObject,
    pub discard_oldest: Boolean,
    pub queue_size: usize,
    pub notification_queue: Vec<NotificationMessage>,
    first_tick: bool,
    last_sample_time: chrono::DateTime<chrono::UTC>,
    queue_overflow: bool,
}

impl MonitoredItem {
    pub fn new(monitored_item_id: UInt32, request: &MonitoredItemCreateRequest) -> MonitoredItem {
        // TODO sampling inteval and queue size should be revised
        let sampling_interval = request.requested_parameters.sampling_interval;
        let queue_size = if request.requested_parameters.queue_size < 1 { 1 } else { request.requested_parameters.queue_size as usize };

        MonitoredItem {
            monitored_item_id: monitored_item_id,
            item_to_monitor: request.item_to_monitor.clone(),
            monitoring_mode: request.monitoring_mode,
            client_handle: request.requested_parameters.client_handle,
            sampling_interval: sampling_interval,
            filter: request.requested_parameters.filter.clone(),
            discard_oldest: request.requested_parameters.discard_oldest,
            last_sample_time: chrono::UTC::now(),
            first_tick: true,
            queue_size: queue_size,
            notification_queue: Vec::with_capacity(queue_size),
            queue_overflow: false
        }
    }

    pub fn get_notification_message(&mut self) -> Option<NotificationMessage> {
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
    pub fn tick(&mut self, now: &chrono::DateTime<chrono::UTC>, subscription_interval_elapsed: bool) -> bool {
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
            if self.first_tick {
                // Always check on the first tick
                self.first_tick = false;
                true
            } else {
                false
            }
        };

        // Test the value (or don't)
        if !check_value {
            false
        } else {
            // TODO
            // Test the value to the last value using filter criteria. If there is no last value (i.e
            // first time monitored item is checked), then in some cases that causes a notification

            // Sequence number will be filled in somewhere else
            let notification_message = NotificationMessage {
                sequence_number: 0,
                publish_time: DateTime::from_chrono(now.clone()),
                notification_data: None,
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

            self.last_sample_time = now.clone();
            true
        }
    }
}