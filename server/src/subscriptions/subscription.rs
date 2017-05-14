use std::collections::{HashMap, BTreeMap};

use chrono;
use time;

use prelude::*;
use constants;

use DateTimeUTC;
use subscriptions::monitored_item::*;
use session::{PublishRequestEntry, PublishResponseEntry};
use address_space::*;

/// Subscription events are passed between the timer thread and the session thread so must
/// be transferable
#[derive(Clone, Debug, PartialEq)]
pub enum SubscriptionEvent {
    PublishResponses(Vec<PublishResponseEntry>),
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

#[derive(Debug)]
pub struct UpdateStateResult {
    pub handled_state: u8,
    pub update_state_action: UpdateStateAction,
}

impl UpdateStateResult {
    pub fn new(handled_state: u8, update_state_action: UpdateStateAction) -> UpdateStateResult {
        UpdateStateResult {
            handled_state: handled_state,
            update_state_action: update_state_action,
        }
    }
}

/// Describes the output of
#[derive(Debug, Clone, PartialEq)]
pub enum UpdateStateAction {
    None,
    ReturnKeepAlive,
    ReturnNotifications,
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
    /// A boolean value that is set to true to reflect that, the last time the publishing timer
    /// expired, there were no Publish requests queued.
    pub late_publish_request: bool,
    /// A value that contains the number of consecutive publishing timer expirations without Client
    /// activity before the Subscription is terminated.
    pub lifetime_counter: UInt32,
    /// boolean value that is set to true to mean that either a NotificationMessage or a keep-alive
    /// Message has been sent on the Subscription. It is a flag that is used to ensure that either
    /// a NotificationMessage or a keep-alive Message is sent out the first time the publishing timer
    /// expires.
    pub message_sent: bool,
    pub keep_alive_counter: UInt32,
    /// A boolean value that is set to true only when there is at least one MonitoredItem that is
    /// in the reporting mode and that has a Notification queued or there is at least one item to
    /// report whose triggering item has triggered and that has a Notification queued.
    pub notifications_available: bool,
    /// The parameter that requests publishing to be enabled or disabled.
    pub publishing_enabled: bool,
    /// A boolean value that is set to true only when there is a Publish request Message queued to
    /// the Subscription.
    pub publishing_req_queued: bool,
    // Notifications waiting to be sent in a map by sequence number. A b-tree is used to ensure ordering is
    // by sequence number.
    pub retransmission_queue: BTreeMap<UInt32, NotificationMessage>,
    // The last monitored item id
    last_monitored_item_id: UInt32,
    // The time that the subscription interval last fired
    last_timer_expired_time: DateTimeUTC,
    /// The value that records the value of the sequence number used in NotificationMessages.
    last_sequence_number: UInt32,
}

impl Subscription {
    pub fn new(subscription_id: UInt32, publishing_enabled: bool, publishing_interval: Double, lifetime_count: UInt32, keep_alive_count: UInt32, priority: Byte) -> Subscription {
        Subscription {
            subscription_id: subscription_id,
            publishing_interval: publishing_interval,
            priority: priority,
            monitored_items: HashMap::with_capacity(constants::DEFAULT_MONITORED_ITEM_CAPACITY),
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
            // Outgoing notifications
            retransmission_queue: BTreeMap::new(),
            // Counters for new items
            last_monitored_item_id: 0,
            last_timer_expired_time: chrono::UTC::now(),
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
            let result = if let Ok(monitored_item) = monitored_item {
                // Return the status
                let result = MonitoredItemCreateResult {
                    status_code: GOOD,
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
                    status_code: monitored_item.unwrap_err(),
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
        let mut result = Vec::with_capacity(items_to_modify.len());
        for item_to_modify in items_to_modify {
            let monitored_item = self.monitored_items.get_mut(&item_to_modify.monitored_item_id);
            if let Some(monitored_item) = monitored_item {
                // Skip items not being reported
                if monitored_item.monitoring_mode != MonitoringMode::Reporting {
                    continue;
                }
                // Try to change the monitored item according to the modify request
                let modify_result = monitored_item.modify(item_to_modify);
                result.push(if modify_result.is_ok() {
                    MonitoredItemModifyResult {
                        status_code: GOOD,
                        revised_sampling_interval: monitored_item.sampling_interval,
                        revised_queue_size: monitored_item.queue_size as UInt32,
                        filter_result: ExtensionObject::null(),
                    }
                } else {
                    MonitoredItemModifyResult {
                        status_code: modify_result.unwrap_err(),
                        revised_sampling_interval: 0f64,
                        revised_queue_size: 0,
                        filter_result: ExtensionObject::null(),
                    }
                });
            } else {
                // Item does not exist
                result.push(MonitoredItemModifyResult {
                    status_code: BAD_MONITORED_ITEM_ID_INVALID,
                    revised_sampling_interval: 0f64,
                    revised_queue_size: 0,
                    filter_result: ExtensionObject::null(),
                });
            }
        }
        result
    }

    /// Delete the specified monitored items (by item id), returning a status code for each
    pub fn delete_monitored_items(&mut self, items_to_delete: &[UInt32]) -> Vec<StatusCode> {
        let mut result = Vec::with_capacity(items_to_delete.len());
        for item_to_delete in items_to_delete {
            // Remove the item (or report an error with the id)
            let removed = self.monitored_items.remove(item_to_delete);
            result.push(if removed.is_some() { GOOD } else { BAD_MONITORED_ITEM_ID_INVALID });
        }
        result
    }

    /// Checks the subscription and monitored items for state change, messages. If the tick does
    /// nothing, the function returns None. Otherwise it returns one or more messages in an Vec.
    pub fn tick(&mut self, address_space: &AddressSpace, receive_publish_request: bool, publish_request: &Option<PublishRequestEntry>, publishing_req_queued: bool, now: &DateTimeUTC) -> (Option<PublishResponseEntry>, Option<UpdateStateResult>) {
        // Test if the interval has elapsed.
        let publishing_timer_expired = if receive_publish_request {
            false
        } else if self.state == SubscriptionState::Creating {
            true
        } else if self.publishing_interval <= 0f64 {
            true
        } else {
            let publishing_interval = time::Duration::milliseconds(self.publishing_interval as i64);
            let elapsed = *now - self.last_timer_expired_time;
            let timer_expired = elapsed >= publishing_interval;
            if timer_expired {
                self.last_timer_expired_time = *now;
            }
            timer_expired
        };

        // Do a tick on monitored items. Note that monitored items normally update when the interval
        // elapses but they don't have to. So this is called every tick just to catch items with their
        // own intervals.
        let items_changed = self.tick_monitored_items(address_space, now, publishing_timer_expired);

        self.publishing_req_queued = publishing_req_queued;
        self.notifications_available = self.retransmission_queue.len() > 0;
        self.more_notifications = self.retransmission_queue.len() > 0;

        // If items have changed or subscription interval elapsed then we may have notifications
        // to send or state to update
        let result = if items_changed || publishing_timer_expired || publish_request.is_some() {
            let update_state_result = self.update_state(receive_publish_request, publish_request, publishing_timer_expired);
            debug!("subscription tick - update_state_result = {:?}", update_state_result);
            let publish_response = match update_state_result.update_state_action {
                UpdateStateAction::None => None,
                UpdateStateAction::ReturnKeepAlive => Some(self.return_keep_alive(publish_request.as_ref().unwrap(), &update_state_result)),
                UpdateStateAction::ReturnNotifications => Some(self.return_notifications(publish_request.as_ref().unwrap(), &update_state_result)),
            };
            debug!("Subscription tick - publish_response = {:?}", publish_response);
            (publish_response, Some(update_state_result))
        } else {
            (None, None)
        };

        // Check if the subscription interval has been exceeded since last call
        if self.lifetime_counter == 1 {
            info!("Subscription {} has expired and will be removed shortly", self.subscription_id);
            self.state = SubscriptionState::Closed;
        }

        result
    }

    /// Return the next sequence number
    fn create_sequence_number(&mut self) -> UInt32 {
        self.last_sequence_number += 1;
        self.last_sequence_number
    }

    /// Iterate through the monitored items belonging to the subscription, calling tick on each in turn.
    /// The function returns true if any of the monitored items due to the subscription interval
    /// elapsing, or their own interval elapsing.
    fn tick_monitored_items(&mut self, address_space: &AddressSpace, now: &DateTimeUTC, publishing_timer_expired: bool) -> bool {
        let mut monitored_item_notifications = Vec::new();
        for (_, monitored_item) in self.monitored_items.iter_mut() {
            if monitored_item.tick(address_space, now, publishing_timer_expired) {
                // Take the monitored item's first notification
                if let Some(mut notification_messages) = monitored_item.remove_all_notification_messages() {
                    monitored_item_notifications.append(&mut notification_messages);
                }
            }
        }
        let result = if monitored_item_notifications.len() > 0 {
            // Create a notification message in the map
            let sequence_number = self.create_sequence_number();
            debug!("Monitored items, seq nr = {}, nr notifications = {}", sequence_number, monitored_item_notifications.len());
            let notification = NotificationMessage::new_data_change(sequence_number, &DateTime::now(), monitored_item_notifications);
            self.retransmission_queue.insert(sequence_number, notification);
            true
        } else {
            false
        };
        result
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
    pub fn update_state(&mut self, receive_publish_request: bool, publish_request: &Option<PublishRequestEntry>, publishing_timer_expired: bool) -> UpdateStateResult {
        // This function is called when a publish request is received OR the timer expired, so getting
        // both is invalid code somewhere
        if receive_publish_request && publishing_timer_expired {
            panic!("Should not be possible for timer to have expired and received publish request at same time")
        }

        // Extra state debugging
        {
            use log::LogLevel::Debug;
            if log_enabled!(Debug) {
                debug!("State inputs:");
                debug!("  subscription_id: {}", self.subscription_id);
                debug!("  state: {:?}", self.state);
                debug!("  receive_publish_request: {:?}", receive_publish_request);
                debug!("  publishing_timer_expired: {}", publishing_timer_expired);
                debug!("  publishing_req_queued: {}", self.publishing_req_queued);
                debug!("  publishing_enabled: {}", self.publishing_enabled);
                debug!("  more_notifications: {}", self.more_notifications);
                debug!("  notifications_available: {} (queue size = {})", self.notifications_available, self.retransmission_queue.len());
                debug!("  keep_alive_counter: {}", self.keep_alive_counter);
                debug!("  lifetime_counter: {}", self.lifetime_counter);
                debug!("  message_sent: {}", self.message_sent);
            }
        }

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
                return UpdateStateResult::new(1, UpdateStateAction::None);
            }
            SubscriptionState::Creating => {
                // State #2
                // CreateSubscription fails, return negative response
                // Handled in message handler

                // State #3
                self.state = SubscriptionState::Normal;
                self.message_sent = false;
                return UpdateStateResult::new(3, UpdateStateAction::None);
            }
            SubscriptionState::Normal => {
                if receive_publish_request {
                    if !self.publishing_enabled || (self.publishing_enabled && !self.more_notifications) {
                        // State #4
                        return UpdateStateResult::new(4, UpdateStateAction::None);
                    } else if self.publishing_enabled && self.more_notifications {
                        // State #5
                        self.reset_lifetime_counter();
                        self.message_sent = true;
                        return UpdateStateResult::new(5, UpdateStateAction::ReturnNotifications);
                    }
                } else if publishing_timer_expired {
                    if self.publishing_req_queued && self.publishing_enabled && self.notifications_available {
                        // State #6
                        self.reset_lifetime_counter();
                        self.start_publishing_timer();
                        self.message_sent = true;
                        return UpdateStateResult::new(6, UpdateStateAction::ReturnNotifications);
                    } else if self.publishing_req_queued && !self.message_sent && (!self.publishing_enabled || (self.publishing_enabled && !self.notifications_available)) {
                        // State #7
                        self.reset_lifetime_counter();
                        self.start_publishing_timer();
                        self.message_sent = true;
                        return UpdateStateResult::new(7, UpdateStateAction::ReturnKeepAlive);
                    } else if !self.publishing_req_queued && (!self.message_sent || (self.publishing_enabled && self.notifications_available)) {
                        // State #8
                        self.start_publishing_timer();
                        self.state = SubscriptionState::Late;
                        return UpdateStateResult::new(8, UpdateStateAction::None);
                    } else if self.message_sent && (!self.publishing_enabled || (self.publishing_enabled && !self.notifications_available)) {
                        // State #9
                        self.start_publishing_timer();
                        self.reset_keep_alive_counter();
                        self.state = SubscriptionState::KeepAlive;
                        return UpdateStateResult::new(9, UpdateStateAction::None);
                    }
                }
            }
            SubscriptionState::Late => {
                if receive_publish_request {
                    if self.publishing_enabled && (self.notifications_available || self.more_notifications) {
                        // State #10
                        self.reset_lifetime_counter();
                        self.state = SubscriptionState::Normal;
                        self.message_sent = true;
                        return UpdateStateResult::new(10, UpdateStateAction::ReturnNotifications);
                    } else if !self.publishing_enabled || (self.publishing_enabled && !self.notifications_available && !self.more_notifications) {
                        // State #11
                        self.reset_lifetime_counter();
                        self.state = SubscriptionState::KeepAlive;
                        self.message_sent = true;
                        return UpdateStateResult::new(11, UpdateStateAction::ReturnKeepAlive);
                    }
                } else if publishing_timer_expired {
                    // State #12
                    self.start_publishing_timer();
                    return UpdateStateResult::new(12, UpdateStateAction::None);
                }
            }
            SubscriptionState::KeepAlive => {
                if receive_publish_request {
                    // State #13
                    return UpdateStateResult::new(13, UpdateStateAction::None);
                } else if publishing_timer_expired {
                    if self.publishing_enabled && self.notifications_available && self.publishing_req_queued {
                        // State #14
                        self.message_sent = true;
                        self.state = SubscriptionState::Normal;
                        return UpdateStateResult::new(14, UpdateStateAction::ReturnNotifications);
                    } else if self.publishing_req_queued && self.keep_alive_counter == 1 && (!self.publishing_enabled || (self.publishing_enabled && self.notifications_available)) {
                        // State #15
                        self.start_publishing_timer();
                        self.reset_keep_alive_counter();
                        return UpdateStateResult::new(15, UpdateStateAction::ReturnKeepAlive);
                    } else if self.keep_alive_counter > 1 && (!self.publishing_enabled || (self.publishing_enabled && !self.notifications_available)) {
                        // State #16
                        self.start_publishing_timer();
                        self.keep_alive_counter -= 1;
                        return UpdateStateResult::new(16, UpdateStateAction::None);
                    } else if !self.publishing_req_queued && (self.keep_alive_counter == 1 || (self.keep_alive_counter > 1 && self.publishing_enabled && self.notifications_available)) {
                        // State #17
                        self.start_publishing_timer();
                        self.state = SubscriptionState::Late;
                        return UpdateStateResult::new(17, UpdateStateAction::None);
                    }
                }
            }
        }

        // Some more state tests that match on more than one state
        match self.state {
            SubscriptionState::Normal | SubscriptionState::Late | SubscriptionState::KeepAlive => {
                if self.lifetime_counter == 1 {
                    // State #27
                    // TODO
                    // delete monitored items
                    // issue_status_change_notification
                }
            }
            _ => {
                // DO NOTHING
            }
        }

        UpdateStateResult::new(0, UpdateStateAction::None)
    }

    pub fn delete_acked_notification_msg(&mut self, subscription_acknowledgement: &SubscriptionAcknowledgement) -> StatusCode {
        if subscription_acknowledgement.subscription_id != self.subscription_id {
            panic!("Code shouldn't call this for wrong subscription_id");
        }
        // Clear notification by sequence number
        if self.retransmission_queue.remove(&subscription_acknowledgement.sequence_number).is_some() {
            info!("Removed acknowledged notification {}", subscription_acknowledgement.sequence_number);
            self.more_notifications = !self.retransmission_queue.is_empty();
            GOOD
        } else {
            error!("Can't find acknowledged notification {}", subscription_acknowledgement.sequence_number);
            BAD_SEQUENCE_NUMBER_UNKNOWN
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
        self.lifetime_counter = self.max_lifetime_count;
    }

    /// Start or restart the publishing timer and decrement the LifetimeCounter Variable.
    pub fn start_publishing_timer(&mut self) {
        self.lifetime_counter -= 1;
    }

    /// CreateKeepAliveMsg()
    /// ReturnResponse()
    pub fn return_keep_alive(&mut self, publish_request: &PublishRequestEntry, update_state_result: &UpdateStateResult) -> PublishResponseEntry {
        let now = DateTime::now();
        let sequence_number = self.create_sequence_number();

        // Empty notification message
        let notification_message = NotificationMessage {
            sequence_number: sequence_number,
            publish_time: now.clone(),
            notification_data: None,
        };

        // Publish response with no notification message
        self.make_publish_response(publish_request, &now, notification_message)
    }

    /// Returns the oldest notification
    pub fn return_notifications(&mut self, publish_request: &PublishRequestEntry, update_state_result: &UpdateStateResult) -> PublishResponseEntry {
        if self.retransmission_queue.is_empty() {
            panic!("Should not be trying to return notifications if there are none");
        }

        debug!("return notifications, len = {}", self.retransmission_queue.len());
        let now = DateTime::now();

        // Find the first notification in the map. The map is ordered so the first item will
        // be the oldest.
        let sequence_number = {
            *self.retransmission_queue.iter().next().unwrap().0
        };
        let notification_message = self.retransmission_queue.get(&sequence_number).unwrap().clone();

        // Make the response
        let publish_response = self.make_publish_response(publish_request, &now, notification_message);

        publish_response
    }

    /// Returns the array of available sequence numbers
    fn available_sequence_numbers(&self) -> Option<Vec<UInt32>> {
        if self.retransmission_queue.is_empty() {
            None
        } else {
            // Turn our sequence numbers into a vector
            Some(self.retransmission_queue.keys().cloned().collect())
        }
    }

    fn make_publish_response(&self, publish_request: &PublishRequestEntry, now: &DateTime, notification_message: NotificationMessage) -> PublishResponseEntry {
        PublishResponseEntry {
            request_id: publish_request.request_id,
            response: PublishResponse {
                response_header: ResponseHeader::new_service_result(now, &publish_request.request.request_header, GOOD),
                subscription_id: self.subscription_id,
                available_sequence_numbers: self.available_sequence_numbers(),
                more_notifications: self.more_notifications,
                notification_message: notification_message,
                results: None,
                diagnostic_infos: None,
            }
        }
    }
}