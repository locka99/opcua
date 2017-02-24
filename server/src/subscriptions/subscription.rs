use std::collections::HashMap;

use opcua_core::types::*;

use subscriptions::monitored_item::*;

/// Subscription events are passed between the timer thread and the session thread so must
/// be transferable
#[derive(Clone, Debug, PartialEq)]
pub enum SubscriptionEvent {
    NotificationMessage(NotificationMessage),
}

/// The state of the subscription
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SubscriptionState {
    Closed,
    Creating,
    Normal,
    Late,
    KeepAlive
}

#[derive(Debug, Clone, PartialEq)]
pub struct Subscription {
    pub subscription_id: UInt32,
    /// Flag enabling publishing
    pub publishing_enabled: Boolean,
    /// State of the subscription
    pub state: SubscriptionState,
    /// Publishing interval
    pub publishing_interval: Double,
    /// Lifetime count enforced
    pub lifetime_count: UInt32,
    /// Keep alive count enforced
    pub keep_alive_count: UInt32,
    /// Relative priority of the subscription. When more than
    /// one subscription needs to send notifications the highest
    /// priority subscription should be sent first.
    pub priority: Byte,
    /// List of monitored items
    pub monitored_items: Vec<MonitoredItem>,
    // Current lifetime counter
    current_lifetime_counter: UInt32,
    // Current keep alive counter
    current_keep_alive_counter: UInt32,
}

impl Subscription {
    pub fn new(subscription_id: UInt32, publishing_interval: Double, lifetime_count: UInt32, keep_alive_count: UInt32, priority: Byte) -> Subscription {
        Subscription {
            subscription_id: subscription_id,
            publishing_enabled: true,
            state: SubscriptionState::Creating,
            publishing_interval: publishing_interval,
            lifetime_count: lifetime_count,
            keep_alive_count: keep_alive_count,
            priority: priority,
            monitored_items: Vec::new(),
            current_lifetime_counter: 0,
            current_keep_alive_counter: 0,
        }
    }

    /// Start the subscription timer that fires on the publishing interval.
    pub fn start_timer(&mut self) {}

    /// Stops the subscription timer that fires on the publishing interval
    pub fn stop_timer(&mut self) {}

    /// Creates monitored items on the specified subscription, returning the creation results
    pub fn create_monitored_items(&mut self, items_to_create: &[MonitoredItemCreateRequest]) -> Vec<MonitoredItemCreateResult> {
        let results = Vec::with_capacity(items_to_create.len());

        // Add items to the subscription if they're not already in its
        for _ in items_to_create {
            // Process items to create here
            /*                    let result = MonitoredItemCreateResult {
            status_code: &GOOD,
            monitored_item_id: UInt32,
            revised_sampling_interval: Double,
            revised_queue_size: UInt32,
            filter_result: ExtensionObject,
        };
        results.push(result); */
        }
        results
    }

    // modify_monitored_items
    // delete_monitored_items

    pub fn tick_subscriptions(subscriptions: &mut HashMap<UInt32, Subscription>) {
        let mut dead_subscriptions: Vec<u32> = Vec::with_capacity(5);
        for (subscription_id, subscription) in subscriptions.iter_mut() {
            // Dead subscriptions will be removed at the end
            if subscription.state == SubscriptionState::Closed {
                dead_subscriptions.push(*subscription_id);
            } else {
                subscription.tick();
            }
        }
        // Remove dead subscriptions
        for subscription_id in dead_subscriptions {
            subscriptions.remove(&subscription_id);
        }
    }

    fn tick(&mut self) {
        debug!("tick");

        self.current_lifetime_counter += 1;
        if self.current_lifetime_counter >= self.lifetime_count {
            debug!("Subscription {} has expired and will be removed shortly", self.subscription_id);
            self.state = SubscriptionState::Closed;
            self.stop_timer();
            return;
        }

        // if publishqueue.pending publish request count = 0 && self.haspendingnotifications() || self.hasmonitoreditemnotifications) {
        // self.state = SubscriptionState::Late;
        // return;
        // }

        // if publishqueue.pending publish request count > 0 {
        //   if self.haspendingnotifications {
        //     self.process_subscription
        //   else if self.hasmonitoreditemnotifications {
        //     self.process.subscription
        //   } else {
        //     self.process_keep_alive()
        // else {
        //     self.process_keep_alive()
        // }
    }

    pub fn reset_lifetime_counter(&mut self) {
        self.current_lifetime_counter = 0;
    }

    pub fn keep_alive(&mut self) {
        self.current_keep_alive_counter += 1;
        if self.current_keep_alive_counter >= self.keep_alive_count {
            if self.send_keep_alive_response() {
                self.current_keep_alive_counter = 0;
                self.current_lifetime_counter = 0;
            } else {
                self.state = SubscriptionState::Late;
            }
        }
    }

    pub fn send_keep_alive_response(&mut self) -> bool {
        // if publisher.send_keep_alive_response(self.subscription_id, futuresequencenr) {
        //    self.state = SubscriptionState::KeepAlive;
        //    true
        // }
        // else {
        //   false
        // }
        true
    }

    pub fn delete_acknowledged_notification_messages() {}

    pub fn enqueue_pushing_request() {}

    pub fn return_notifications() {}

    pub fn start_publishing_timer() {}

    pub fn dequeue_pubish_request() {}

    pub fn return_keep_alive() {}

    pub fn reset_keep_alive_counter() {}
}