use std::collections::{HashMap, BTreeMap};

use chrono;
use time;

use opcua_core::types::*;
use opcua_core::comms::*;

use DateTimeUTC;
use subscriptions::monitored_item::*;
use address_space::*;

/// Subscription events are passed between the timer thread and the session thread so must
/// be transferable
#[derive(Clone, Debug, PartialEq)]
pub enum SubscriptionEvent {
    Messages(Vec<SupportedMessage>),
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

/// Describes the output of
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum UpdateStateAction {
    None,
    ReturnKeepAlive,
    ReturnNotifications
}

/// Describes what to do with the publish request (if any)
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum PublishRequestAction {
    None,
    Dequeue
}

#[derive(Debug, Clone, PartialEq)]
pub struct Subscription {
    pub subscription_id: UInt32,
    /// Publishing interval
    pub publishing_interval: Duration,
    /// The max lifetime count (not the current lifetime count)
    pub max_lifetime_count: UInt32,
    /// Keep alive count enforced
    pub max_keep_alive_count: UInt32,
    /// Relative priority of the subscription. When more than
    /// one subscription needs to send notifications the highest
    /// priority subscription should be sent first.
    pub priority: Byte,
    /// Map of monitored items
    pub monitored_items: HashMap<UInt32, MonitoredItem>,
    /// State of the subscription
    pub state: SubscriptionState,
    /// A boolean value that is set to TRUE only by the CreateNotificationMsg() when there were too
    /// many Notifications for a single NotificationMessage.
    pub more_notifications: bool,
    /// A boolean value that is set to TRUE to reflect that, the last time the publishing timer
    /// expired, there were no Publish requests queued.
    pub late_publish_request: bool,
    /// A value that contains the number of consecutive publishing timer expirations without Client
    /// activity before the Subscription is terminated.
    pub lifetime_counter: UInt32,
    /// boolean value that is set to TRUE to mean that either a NotificationMessage or a keep-alive
    /// Message has been sent on the Subscription. It is a flag that is used to ensure that either
    /// a NotificationMessage or a keep-alive Message is sent out the first time the publishing timer
    /// expires.
    pub message_sent: bool,
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
    /// A boolean value that is set to TRUE only when the Subscription requested to be deleted is
    /// assigned to the Client that issued the request. A Subscription is assigned to the Client
    /// that created it. That assignment can only be changed through successful completion of the
    /// TransferSubscriptions Service.
    pub subscription_assigned_to_client: bool,
    // Outgoing notifications in a map by sequence number. A b-tree is used to ensure ordering is
    // by sequence number.
    pub notifications: BTreeMap<UInt32, NotificationMessage>,
    // The last monitored item id
    last_monitored_item_id: UInt32,
    // The time that the subscription interval last fired
    last_sample_time: DateTimeUTC,
    /// The value that records the value of the sequence number used in NotificationMessages.
    last_sequence_number: UInt32,
}

const DEFAULT_MONITORED_ITEM_CAPACITY: usize = 100;

impl Subscription {
    pub fn new(subscription_id: UInt32, publishing_enabled: bool, publishing_interval: Double, lifetime_count: UInt32, keep_alive_count: UInt32, priority: Byte) -> Subscription {
        Subscription {
            subscription_id: subscription_id,
            publishing_interval: publishing_interval,
            priority: priority,
            monitored_items: HashMap::with_capacity(DEFAULT_MONITORED_ITEM_CAPACITY),
            max_lifetime_count: lifetime_count,
            max_keep_alive_count: keep_alive_count,
            // State variables
            state: SubscriptionState::Creating,
            more_notifications: false,
            late_publish_request: false,
            notifications_available: false,
            lifetime_counter: lifetime_count,
            keep_alive_counter: keep_alive_count,
            message_sent: false,
            publishing_enabled: publishing_enabled,
            publishing_req_queued: false,
            requested_message_found: false,
            subscription_assigned_to_client: true,
            // Outgoing notifications
            notifications: BTreeMap::new(),
            // Counters for new items
            last_monitored_item_id: 0,
            last_sample_time: chrono::UTC::now(),
            last_sequence_number: 0,
        }
    }

    /// Creates monitored items on the specified subscription, returning the creation results
    pub fn create_monitored_items(&mut self, items_to_create: &[MonitoredItemCreateRequest]) -> Vec<MonitoredItemCreateResult> {
        let mut results = Vec::with_capacity(items_to_create.len());
        // Add items to the subscription if they're not already in its
        for item_to_create in items_to_create {
            self.last_monitored_item_id += 1;
            // Process items to create here
            let monitored_item_id = self.last_monitored_item_id;

            // Create a monitored item, if possible
            let monitored_item = MonitoredItem::new(monitored_item_id, item_to_create);
            let result = if monitored_item.is_ok() {
                let monitored_item = monitored_item.unwrap();

                // Return the status
                let result = MonitoredItemCreateResult {
                    status_code: GOOD.clone(),
                    monitored_item_id: monitored_item_id,
                    revised_sampling_interval: monitored_item.sampling_interval,
                    revised_queue_size: monitored_item.queue_size as UInt32,
                    filter_result: ExtensionObject::null()
                };

                // Register the item with the subscription
                self.monitored_items.insert(monitored_item_id, monitored_item);

                result
            } else {
                // Monitored item couldn't be created
                MonitoredItemCreateResult {
                    status_code: monitored_item.unwrap_err().clone(),
                    monitored_item_id: monitored_item_id,
                    revised_sampling_interval: 0f64,
                    revised_queue_size: 0,
                    filter_result: ExtensionObject::null()
                }
            };
            results.push(result);
        }
        results
    }

    /// Modify the specified monitored items, returning a result for each
    pub fn modify_monitored_items(&mut self, items_to_modify: &[MonitoredItemModifyRequest]) -> Vec<MonitoredItemModifyResult> {
        // TODO Implement
        let mut result = Vec::with_capacity(items_to_modify.len());
        for item_to_modify in items_to_modify {
            result.push(MonitoredItemModifyResult {
                status_code: BAD_MONITORED_ITEM_ID_INVALID.clone(),
                revised_sampling_interval: 0f64,
                revised_queue_size: 0,
                filter_result: ExtensionObject::null(),
            });
        }
        result
    }

    /// Delete the specified monitored items (by item id), returning a status code for each
    pub fn delete_monitored_items(&mut self, items_to_delete: &[UInt32]) -> Vec<StatusCode> {
        // TODO Implement
        let mut result = Vec::with_capacity(items_to_delete.len());
        for item_to_delete in items_to_delete {
            result.push(BAD_MONITORED_ITEM_ID_INVALID.clone());
        }
        result
    }

    /// Checks the subscription and monitored items for state change, messages. If the tick does
    /// nothing, the function returns None. Otherwise it returns one or more messages in an Vec.
    pub fn tick(&mut self, address_space: &AddressSpace, publish_request: &Option<PublishRequest>, now: &DateTimeUTC) -> (Option<NotificationMessage>, PublishRequestAction) {
        debug!("subscription tick {}", self.subscription_id);

        // Test if the interval has elapsed.
        let publishing_timer_expired = if self.state == SubscriptionState::Creating {
            true
        } else if self.publishing_interval <= 0f64 {
            true
        } else {
            let publishing_interval = time::Duration::milliseconds(self.publishing_interval as i64);
            let elapsed = *now - self.last_sample_time;
            elapsed >= publishing_interval
        };

        // Do a tick on monitored items. Note that monitored items normally update when the interval
        // elapses but they don't have to. So this is called every tick just to catch items with their
        // own intervals.
        let items_changed = self.tick_monitored_items(address_space, now, publishing_timer_expired);

        // If items have changed or subscription interval elapsed then we may have notifications
        // to send or state to update
        let result = if items_changed || publishing_timer_expired {
            let (_, update_state_action, publish_request_action) = self.update_state(publish_request, publishing_timer_expired);
            let notifications = match update_state_action {
                UpdateStateAction::None => None,
                UpdateStateAction::ReturnKeepAlive => self.return_keep_alive(),
                UpdateStateAction::ReturnNotifications => self.return_notifications(),
            };
            (notifications, publish_request_action)
        } else {
            (None, PublishRequestAction::None)
        };

        // Check if the subscription interval has been exceeded since last call
        if self.lifetime_counter == 1 {
            debug! ("Subscription {} has expired and will be removed shortly", self.subscription_id);
            self.state = SubscriptionState::Closed;
        }

        result
    }

    /// Iterate through the monitored items belonging to the subscription, calling tick on each in turn.
    /// The function returns true if any of the monitored items due to the subscription interval
    /// elapsing, or their own interval elapsing.
    fn tick_monitored_items(&mut self, address_space: &AddressSpace, now: &DateTimeUTC, subscription_interval_elapsed: bool) -> bool {
        let mut monitored_item_notifications = Vec::new();
        for (_, monitored_item) in self.monitored_items.iter_mut() {
            if monitored_item.tick(address_space, now, subscription_interval_elapsed) {
                // Take the monitored item's first notification
                monitored_item_notifications.push(monitored_item.get_notification_message().unwrap());
            }
        }
        if !monitored_item_notifications.is_empty() {
            // Create a notification message in the map
            self.last_sequence_number += 1;
            let sequence_number = self.last_sequence_number;
            let notification = NotificationMessage::new_data_change(sequence_number, &DateTime::now(), monitored_item_notifications);
            self.notifications.insert(sequence_number, notification);
            true
        } else {
            false
        }
    }

    // See OPC UA Part 4 5.13.1.2 State Table
    //
    // This function implements the main guts of updating the subscription's state according to
    // some input events and its existing internal state.
    //
    // Calls to the function will update the internal state of and return a tuple with any required
    // actions.
    //
    // Note that some state events are handled outside of update_state. e.g. the subscription
    // is created elsewhere which handles states 1, 2 and 3.
    //
    // Inputs:
    //
    // * publish_request - an optional publish request. May be used by subscription to remove acknowledged notifications
    // * publishing_timer_expired - true if state is being updated in response to the subscription timer firing
    //
    // Returns in order:
    //
    // * State id that handled this call. Useful for debugging which state handler triggered
    // * Update state action - none, return notifications, return keep alive
    // * Publishing request action - nothing, dequeue
    //
    pub fn update_state(&mut self, publish_request: &Option<PublishRequest>, publishing_timer_expired: bool) -> (u8, UpdateStateAction, PublishRequestAction) {
        let receive_publish_request = publish_request.is_some();

        // This is a state engine derived from OPC UA Part 4 Publish service and might look a
        // little odd for that.
        //
        // Note in some cases, some of the actions have already happened outside of this function.
        // For example, publish requests are already queued before we come in here and this function
        // uses what its given. Likewise, this function does not "send" notifications, rather
        // it returns them (if any) and it is up to the caller to send them

        match self.state {
            SubscriptionState::Closed => {
                // State #1
                // TODO
                // if receive_create_subscription {
                // self.state = Subscription::Creating;
                // }
                return (1, UpdateStateAction::None, PublishRequestAction::None);
            }
            SubscriptionState::Creating => {
                // State #2
                // CreateSubscription fails, return negative response
                // Handled in message handler

                // State #3
                self.state = SubscriptionState::Normal;
                self.message_sent = false;
                return (3, UpdateStateAction::None, PublishRequestAction::None);
            }
            SubscriptionState::Normal => {
                if receive_publish_request && (!self.publishing_enabled || (self.publishing_enabled && !self.more_notifications)) {
                    // State #4
                    let publish_request = publish_request.as_ref().unwrap();
                    self.delete_acked_notification_msgs(publish_request);
                    return (4, UpdateStateAction::None, PublishRequestAction::None);
                } else if receive_publish_request && self.publishing_enabled && self.more_notifications {
                    // State #5
                    self.reset_lifetime_counter();
                    self.delete_acked_notification_msgs(publish_request.as_ref().unwrap());
                    self.message_sent = true;
                    return (5, UpdateStateAction::ReturnNotifications, PublishRequestAction::None);
                } else if publishing_timer_expired && self.publishing_req_queued && self.publishing_enabled && self.notifications_available {
                    // State #6
                    self.reset_lifetime_counter();
                    self.start_publishing_timer();
                    self.message_sent = true;
                    return (6, UpdateStateAction::ReturnNotifications, PublishRequestAction::Dequeue);
                } else if publishing_timer_expired && self.publishing_req_queued && !self.message_sent && (!self.publishing_enabled || (self.publishing_enabled && !self.notifications_available)) {
                    // State #7
                    self.reset_lifetime_counter();
                    self.start_publishing_timer();
                    self.message_sent = true;
                    return (7, UpdateStateAction::ReturnKeepAlive, PublishRequestAction::Dequeue);
                } else if publishing_timer_expired && !self.publishing_req_queued && (!self.message_sent || (self.publishing_enabled && self.notifications_available)) {
                    // State #8
                    self.start_publishing_timer();
                    self.state = SubscriptionState::Late;
                    return (8, UpdateStateAction::None, PublishRequestAction::None);
                } else if publishing_timer_expired && self.message_sent && (!self.publishing_enabled || (self.publishing_enabled && !self.notifications_available)) {
                    // State #9
                    self.start_publishing_timer();
                    self.reset_keep_alive_counter();
                    self.state = SubscriptionState::KeepAlive;
                    return (9, UpdateStateAction::None, PublishRequestAction::None);
                }
            }
            SubscriptionState::Late => {
                if receive_publish_request && self.publishing_enabled && (self.notifications_available || self.more_notifications) {
                    // State #10
                    self.reset_lifetime_counter();
                    self.delete_acked_notification_msgs(publish_request.as_ref().unwrap());
                    self.state = SubscriptionState::Normal;
                    self.message_sent = true;
                    return (10, UpdateStateAction::ReturnNotifications, PublishRequestAction::None);
                } else if receive_publish_request && (!self.publishing_enabled || (self.publishing_enabled && !self.notifications_available && !self.more_notifications)) {
                    // State #11
                    self.reset_lifetime_counter();
                    self.delete_acked_notification_msgs(publish_request.as_ref().unwrap());
                    self.state = SubscriptionState::KeepAlive;
                    self.message_sent = true;
                    return (11, UpdateStateAction::ReturnKeepAlive, PublishRequestAction::None);
                } else if publishing_timer_expired {
                    // State #12
                    self.start_publishing_timer();
                    return (12, UpdateStateAction::None, PublishRequestAction::None);
                }
            }
            SubscriptionState::KeepAlive => {
                if receive_publish_request {
                    // State #13
                    self.delete_acked_notification_msgs(publish_request.as_ref().unwrap());
                    return (13, UpdateStateAction::None, PublishRequestAction::None);
                } else if publishing_timer_expired && self.publishing_enabled && self.notifications_available && self.publishing_req_queued {
                    // State #14
                    self.message_sent = true;
                    self.state = SubscriptionState::Normal;
                    return (14, UpdateStateAction::ReturnNotifications, PublishRequestAction::Dequeue);
                } else if publishing_timer_expired && self.publishing_req_queued && self.keep_alive_counter == 1 &&
                    !self.publishing_enabled || (self.publishing_enabled && self.notifications_available) {
                    // State #15
                    self.start_publishing_timer();
                    self.reset_keep_alive_counter();
                    return (15, UpdateStateAction::ReturnKeepAlive, PublishRequestAction::Dequeue);
                } else if publishing_timer_expired && self.keep_alive_counter > 1 && (!self.publishing_enabled || (self.publishing_enabled && !self.notifications_available)) {
                    // State #16
                    self.start_publishing_timer();
                    self.keep_alive_counter -= 1;
                    return (16, UpdateStateAction::None, PublishRequestAction::None);
                } else if publishing_timer_expired && !self.publishing_req_queued && (self.keep_alive_counter == 1 || (self.keep_alive_counter > 1 && self.publishing_enabled && self.notifications_available)) {
                    // State #17
                    self.start_publishing_timer();
                    self.state = SubscriptionState::Late;
                    return (17, UpdateStateAction::None, PublishRequestAction::None);
                }
            }
        }

        // Some more state tests that match on more than one state
        match self.state {
            SubscriptionState::Normal | SubscriptionState::Late | SubscriptionState::KeepAlive => {
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
            _ => {
                // DO NOTHING
            }
        }

        (0, UpdateStateAction::None, PublishRequestAction::None)
    }

    /// Deletes the acknowledged notifications, returning a list of status code for each according
    /// to whether it was found or not.
    ///
    /// GOOD - deleted notification
    /// BAD_SUBSCRIPTION_ID_INVALID - Subscription doesn't exist
    /// BAD_SEQUENCE_NUMBER_UNKNOWN - Sequence number doesn't exist
    pub fn delete_acked_notification_msgs(&mut self, request: &PublishRequest) -> Option<Vec<StatusCode>> {
        if request.subscription_acknowledgements.is_none() {
            None
        } else {
            let mut results = Vec::new();
            let subscription_acknowledgements = request.subscription_acknowledgements.as_ref().unwrap();
            for ack in subscription_acknowledgements {
                let result = if ack.subscription_id != self.subscription_id {
                    &BAD_SUBSCRIPTION_ID_INVALID
                } else {
                    // Clear notification by sequence number
                    let removed_notification = self.notifications.remove(&ack.sequence_number);
                    if removed_notification.is_some() {
                        &GOOD
                    } else {
                        &BAD_SEQUENCE_NUMBER_UNKNOWN
                    }
                };
                results.push(result.clone());
            }
            Some(results)
        }
    }

    /// Reset the keep-alive counter to the maximum keep-alive count of the Subscription.
    /// The maximum keep-alive count is set by the Client when the Subscription is created
    /// and may be modified using the ModifySubscription Service
    pub fn reset_keep_alive_counter(&mut self) {
        self.keep_alive_counter = self.max_keep_alive_count;
    }

    /// Reset the lifetime counter to the value specified for the life time of the subscription
    /// in the create subscription service
    pub fn reset_lifetime_counter(&mut self) {
        println!("Setting lifetime_counter to {}", self.max_lifetime_count);
        self.lifetime_counter = self.max_lifetime_count;
    }

    /// Start or restart the publishing timer and decrement the LifetimeCounter Variable.
    pub fn start_publishing_timer(&mut self) {}

    /// CreateKeepAliveMsg()
    /// ReturnResponse()
    pub fn return_keep_alive(&mut self) -> Option<NotificationMessage> {
        // TODO keep alive message
        None
    }

    pub fn return_notifications(&mut self) -> Option<NotificationMessage> {
        if self.notifications.len() > 0 {
            // If (MoreNotifications == TRUE) && (PublishingReqQueued == TRUE)
            // {
            //   DequeuePublishReq()
            //   Loop through this function again
            // }
            let first_key = {
                *self.notifications.iter().next().unwrap().0
            };
            let result = self.notifications.remove(&first_key);
            self.more_notifications = !self.notifications.is_empty();
            result
        } else {
            None
        }
    }
}