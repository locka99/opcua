use std::collections::HashMap;

use chrono;

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
pub struct SubscriptionStateVariables {
    /// A boolean value that is set to TRUE only by the CreateNotificationMsg() when there were too
    /// many Notifications for a single NotificationMessage.
    pub more_notifications: bool,
    /// A boolean value that is set to TRUE to reflect that, the last time the publishing timer
    /// expired, there were no Publish requests queued.
    pub late_publish_request: bool,
    /// A value that contains the number of consecutive publishing timer expirations without Client
    /// activity before the Subscription is terminated.
    pub lifetime_counter: UInt32,
    pub keep_alive_counter: UInt32,
    /// A boolean value that is set to TRUE only when there is at least one MonitoredItem that is
    /// in the reporting mode and that has a Notification queued or there is at least one item to
    /// report whose triggering item has triggered and that has a Notification queued. The
    /// transition of this state Variable from FALSE to TRUE creates the “New Notification Queued”
    /// Event in the state table.
    pub notifications_available: bool,
    /// The parameter that requests publishing to be enabled or disabled.
    pub publishing_enabled: bool,
    /// A boolean value that is set to TRUE only when there is a Publish request Message queued to
    /// the Subscription.
    pub publishing_req_queued: bool,
    /// A boolean value that is set to TRUE only when the Message requested to be retransmitted was found in the retransmission queue.
    pub requested_message_found: bool,
    /// The value that records the value of the sequence number used in NotificationMessages.
    pub seq_num: UInt32,
    /// A boolean value that is set to TRUE only when the Subscription requested to be deleted is
    /// assigned to the Client that issued the request. A Subscription is assigned to the Client
    /// that created it. That assignment can only be changed through successful completion of the
    /// TransferSubscriptions Service.
    pub subscription_assigned_to_client: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Subscription {
    pub subscription_id: UInt32,
    /// Publishing interval
    pub publishing_interval: Double,
    /// The max lifetime count (not the current lifetime count)
    pub lifetime_count: UInt32,
    /// Keep alive count enforced
    pub keep_alive_count: UInt32,
    /// Relative priority of the subscription. When more than
    /// one subscription needs to send notifications the highest
    /// priority subscription should be sent first.
    pub priority: Byte,
    /// Map of monitored items
    pub monitored_items: HashMap<UInt32, MonitoredItem>,
    // The last monitored item id
    last_monitored_item_id: UInt32,
    // The time that the subscription interval last fired
    last_subscription_interval: chrono::DateTime<chrono::UTC>,
    /// State of the subscription
    state: SubscriptionState,
    /// The current subscription state
    subscription_state_variables: SubscriptionStateVariables
}

impl Subscription {
    pub fn new(subscription_id: UInt32, publishing_interval: Double, lifetime_count: UInt32, keep_alive_count: UInt32, priority: Byte) -> Subscription {
        Subscription {
            subscription_id: subscription_id,
            state: SubscriptionState::Creating,
            publishing_interval: publishing_interval,
            priority: priority,
            monitored_items: HashMap::with_capacity(100),
            lifetime_count: lifetime_count,
            keep_alive_count: keep_alive_count,

            last_monitored_item_id: 0,
            last_subscription_interval: chrono::UTC::now(),

            subscription_state_variables: SubscriptionStateVariables {
                // These are all subscription state variables
                more_notifications: false,
                late_publish_request: false,
                notifications_available: false,
                lifetime_counter: 0,
                keep_alive_counter: 0,
                publishing_enabled: true,
                publishing_req_queued: false,
                requested_message_found: false,
                seq_num: 0,
                subscription_assigned_to_client: true,
            }
        }
    }

    /// Start the subscription timer that fires on the publishing interval.
    pub fn start_timer(&mut self) {}

    /// Stops the subscription timer that fires on the publishing interval
    pub fn stop_timer(&mut self) {}

    /// Creates monitored items on the specified subscription, returning the creation results
    pub fn create_monitored_items(&mut self, items_to_create: &[MonitoredItemCreateRequest]) -> Vec<MonitoredItemCreateResult> {
        let mut results = Vec::with_capacity(items_to_create.len());
        // Add items to the subscription if they're not already in its
        for item_to_create in items_to_create {
            self.last_monitored_item_id += 1;
            // Process items to create here
            let monitored_item_id = self.last_monitored_item_id;
            let monitored_item = MonitoredItem::new(monitored_item_id, item_to_create);

            // Return the status
            let result = MonitoredItemCreateResult {
                status_code: GOOD.clone(),
                monitored_item_id: monitored_item_id,
                revised_sampling_interval: monitored_item.sampling_interval,
                revised_queue_size: monitored_item.queue_size as UInt32,
                filter_result: ExtensionObject::null(),
                // TODO
            };

            // Register the item with the subscription
            self.monitored_items.insert(monitored_item_id, monitored_item);

            results.push(result);
        }
        results
    }

    // modify_monitored_items
    // delete_monitored_items

    pub fn tick_subscriptions(subscriptions: &mut HashMap<UInt32, Subscription>) {
        let mut dead_subscriptions: Vec<u32> = Vec::with_capacity(5);

        let now = chrono::UTC::now();
        for (subscription_id, subscription) in subscriptions.iter_mut() {
            // Dead subscriptions will be removed at the end
            if subscription.state == SubscriptionState::Closed {
                dead_subscriptions.push(*subscription_id);
            } else {
                subscription.tick(&now);
            }
        }
        // Remove dead subscriptions
        for subscription_id in dead_subscriptions {
            subscriptions.remove(&subscription_id);
        }
    }

    fn update_state_variables(&mut self) {

    }

    fn tick(&mut self, now: &chrono::DateTime<chrono::UTC>) {
        debug!("subscription tick {}", self.subscription_id);

        self.update_state_variables();

        match self.state {
            SubscriptionState::Creating => {
                // TODO return a response
                self.state = SubscriptionState::Normal;
            },
            SubscriptionState::Normal => {
                // State #4
                // if receive publish request && publishing_enabled == false || (publishing_enabled && !more_notifications) {
                //   delete_acked_notification_msgs
                //   enequeuepublishing_req
                // }
                // State #5
                // else if receive publish_request && pubslihing_enabled && more notifications {
                //    reset_lifetime_counter
                //    delete_acked_notification_msgs
                //    return notifications
                //    message_sent = true
                // }
                // State #6
                // else if publishing_timer_expires && pubishing_req_queued && publishing_enabled && notifications_available {
                //    reset_lifetime_counter
                //    start_publishing_timer
                //    dequeue_publish_request
                //    return notifications
                //    message_sent = true
                // }
                // State #7
                // else if publishing_timer_expires && publishing_req_queue && !message_sent && (!publishing_enabled || publishing_enabled && !notifications_available) {
                //    reset_lifetime_counter
                //    start_publishing_timer
                //    dequeue_publish_request
                //    return_keep_alive
                //    message_sent = true
                // }
                // State #8
                // else if publishing_timer_expires  && !publishing_request_queued && (!message_sent || (publishing_enabled && notifications_available) {
                //    start_publishing_timer
                //    self.state = SubscriptionState::Late
                // }
                // State #9
                // else if publishing_timer_expires && message_sent && (!publishing_enabled || (publishing_enabled && !notifications_available) {
                //    start_publishing_timer
                //    reset_keep_alive_counter
                //    self.state = SubscriptionState::KeepAlive
                // }
            },
            SubscriptionState::Late => {
                // State #10
                // if receive_publish_request && publishing_enabled && (notifications_available || more_notifications) {
                //   reset_lifetime_counter
                //   delete_acked_notification_msgs
                //   return_notifications
                //   message_sent = true
                //   self.state = SubscriptionState::Normal
                // }
                // State #11
                // else if receive_publish_request && (!publishing_enabled || (publishing_enabled && !notifications_available && !more_notifications) {
                //   reset_lifetime_counter
                //   delete_acked_notifications_msgs
                //   return_keep_alive
                //   message_sent = true
                //   self.state = SubscriptionState::KeepAlive
                // }
                // State #12
                // else if publishing_timer_expires {
                //   start_publishing_timer
                // }
            },
            SubscriptionState::KeepAlive => {
                // State #13
                // if receive_publish_request {
                //   delete_acked_notification_msgs
                //   enqueue_publishing_req
                // }
                // State #14
                // else if publishing_timer_expires && publishing_enabled && notifications_available && publishing_req_queued {
                //   dequeue_publish_req
                //   return_notifications
                //   message_sent = true
                //   self.state = SubscriptionState::Normal
                // }
                // State #15
                // else if publishing_timer_expires && publishing_req_queued && keep_alive_counter == 1 &&
                //     !publishing_enabled || (publishing_enabled && notifications_available) {
                //   start_publishing_timer()
                //   dequeue_publish_req
                //   return_keep_alive()
                //   reset_keep_alive_counter()
                // }
                // State #16
                // else if publishing_timer_expires && keep_alive_counter > 1 && (!publishing_enabled || (publishing_enabled && !notifications_available)) {
                //   start_publishing_timer;
                //   self.keep_alive_counter -= 1
                // }
                // State #17
                // else if publishing_timer_expires && !publishing_req_queued && (keep_alive_counter == 1 || (keep_alive_counter > 1 && publishing_enabled && notifications_available) {
                //   start_publishing_timer
                //   self.state = SubscriptionState::Late
                // }
            },
            _ => {
                // DO NOTHING
                return;
            }

            // State #18 receive modifysubscription
            // State #19 receive setpublishingmode
            // State #20 receive republishrequest
            // State #21 receive transfersubscriptions
            // State #22 receive transfersubscriptions
            // State #23 receive transfersubscriptions
            // State #24 receive deletesubscriptions
            // State #25 receive deletesubscriptions
            // State #26 receive deletesubscriptions
            // State #27 lifetimecounter == 1
        }

        // Check if the subscription interval has been exceeded since last call

        self.subscription_state_variables.lifetime_counter += 1;
        if self.subscription_state_variables.lifetime_counter >= self.lifetime_count {
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
        self.subscription_state_variables.lifetime_counter = 0;
    }

    pub fn keep_alive(&mut self) {
        self.subscription_state_variables.keep_alive_counter += 1;
        if self.subscription_state_variables.keep_alive_counter >= self.keep_alive_count {
            if self.send_keep_alive_response() {
                self.subscription_state_variables.keep_alive_counter = 0;
                self.subscription_state_variables.lifetime_counter = 0;
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