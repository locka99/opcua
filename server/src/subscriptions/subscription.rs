use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono;
use time;

use opcua_types::*;
use opcua_types::status_codes::StatusCode;
use opcua_types::status_codes::StatusCode::*;
use opcua_types::service_types::{TimestampsToReturn, NotificationMessage, MonitoredItemCreateRequest, MonitoredItemCreateResult, MonitoredItemModifyRequest, MonitoredItemModifyResult};

use constants;
use DateTimeUtc;
use subscriptions::monitored_item::MonitoredItem;
use address_space::address_space::AddressSpace;
use diagnostics::ServerDiagnostics;

/// The state of the subscription
#[derive(Debug, Copy, Clone, PartialEq, Serialize)]
pub enum SubscriptionState {
    Closed,
    Creating,
    Normal,
    Late,
    KeepAlive,
}

#[derive(Debug)]
pub struct SubscriptionStateParams {
    pub notifications_available: bool,
    pub more_notifications: bool,
    pub publishing_req_queued: bool,
    pub publishing_interval_elapsed: bool,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum UpdateStateAction {
    None,
    ReturnKeepAlive,
    ReturnNotifications,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum HandledState {
    None0 = 0,
    Closed1 = 1,
    // Create2 = 2,
    Create3 = 3,
    Normal4 = 4,
    Normal5 = 5,
    IntervalElapsed6 = 6,
    IntervalElapsed7 = 7,
    IntervalElapsed8 = 8,
    IntervalElapsed9 = 9,
    Late10 = 10,
    Late11 = 11,
    Late12 = 12,
    KeepAlive13 = 13,
    KeepAlive14 = 14,
    KeepAlive15 = 15,
    KeepAlive16 = 16,
    KeepAlive17 = 17,

}


#[derive(Debug)]
pub struct UpdateStateResult {
    pub handled_state: HandledState,
    pub update_state_action: UpdateStateAction,
}

impl UpdateStateResult {
    pub fn new(handled_state: HandledState, update_state_action: UpdateStateAction) -> UpdateStateResult {
        UpdateStateResult {
            handled_state,
            update_state_action,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TickReason {
    ReceivedPublishRequest,
    TickTimerFired,
}

#[derive(Debug, Clone, Serialize)]
pub struct Subscription {
    /// Subscription id
    pub subscription_id: UInt32,
    /// Publishing interval
    pub publishing_interval: Duration,
    /// The max lifetime count (not the current lifetime count)
    pub max_lifetime_count: UInt32,
    /// Keep alive count enforced
    pub max_keep_alive_count: UInt32,
    /// Relative priority of the subscription. When more than one subscriptio
    ///  needs to send notifications the highest priority subscription should
    /// be sent first.
    pub priority: Byte,
    /// Map of monitored items
    pub monitored_items: HashMap<UInt32, MonitoredItem>,
    /// State of the subscription
    pub state: SubscriptionState,
    /// A value that contains the number of consecutive publishing timer expirations without Client
    /// activity before the Subscription is terminated.
    pub lifetime_counter: UInt32,
    /// Keep alive counter decrements when there are no notifications to publish and when it expires
    /// requests to send an empty notification as a keep alive event
    pub keep_alive_counter: UInt32,
    /// boolean value that is set to true to mean that either a NotificationMessage or a keep-alive
    /// Message has been sent on the Subscription. It is a flag that is used to ensure that either
    /// a NotificationMessage or a keep-alive Message is sent out the first time the publishing timer
    /// expires.
    pub message_sent: bool,
    /// The parameter that requests publishing to be enabled or disabled.
    pub publishing_enabled: bool,
    /// The next sequence number to be sent
    next_sequence_number: UInt32,
    // The last monitored item id
    last_monitored_item_id: UInt32,
    // The time that the subscription interval last fired
    last_timer_expired_time: DateTimeUtc,
    /// Server diagnostics to track creation / destruction / modification of the subscription
    #[serde(skip)]
    diagnostics: Arc<RwLock<ServerDiagnostics>>,
    /// Stops the subscription calling diagnostics on drop
    #[serde(skip)]
    pub diagnostics_on_drop: bool,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if self.diagnostics_on_drop {
            let mut diagnostics = trace_write_lock_unwrap!(self.diagnostics);
            diagnostics.on_destroy_subscription(self);
        }
    }
}

impl Subscription {
    pub fn new(diagnostics: Arc<RwLock<ServerDiagnostics>>, subscription_id: UInt32, publishing_enabled: bool, publishing_interval: Double, lifetime_count: UInt32, keep_alive_count: UInt32, priority: Byte) -> Subscription {
        let subscription = Subscription {
            subscription_id,
            publishing_interval,
            priority,
            monitored_items: HashMap::with_capacity(constants::DEFAULT_MONITORED_ITEM_CAPACITY),
            max_lifetime_count: lifetime_count,
            max_keep_alive_count: keep_alive_count,
            // State variables
            state: SubscriptionState::Creating,
            lifetime_counter: lifetime_count,
            keep_alive_counter: keep_alive_count,
            message_sent: false,
            publishing_enabled,
            // Counters for new items
            next_sequence_number: 1,
            last_monitored_item_id: 0,
            last_timer_expired_time: chrono::Utc::now(),
            diagnostics,
            diagnostics_on_drop: true,
        };
        {
            let mut diagnostics = trace_write_lock_unwrap!(subscription.diagnostics);
            diagnostics.on_create_subscription(&subscription);
        }
        subscription
    }

    /// Creates monitored items on the specified subscription, returning the creation results
    pub fn create_monitored_items(&mut self, timestamps_to_return: TimestampsToReturn, items_to_create: &[MonitoredItemCreateRequest]) -> Vec<MonitoredItemCreateResult> {
        let mut results = Vec::with_capacity(items_to_create.len());
        // Add items to the subscription if they're not already in its
        for item_to_create in items_to_create {
            self.last_monitored_item_id += 1;
            // Process items to create here
            let monitored_item_id = self.last_monitored_item_id;
            // Create a monitored item, if possible
            let monitored_item = MonitoredItem::new(monitored_item_id, timestamps_to_return, item_to_create);
            let result = if let Ok(monitored_item) = monitored_item {
                // Return the status
                let result = MonitoredItemCreateResult {
                    status_code: Good,
                    monitored_item_id,
                    revised_sampling_interval: monitored_item.sampling_interval,
                    revised_queue_size: monitored_item.queue_size as UInt32,
                    filter_result: ExtensionObject::null(),
                };
                // Register the item with the subscription
                self.monitored_items.insert(monitored_item_id, monitored_item);
                result
            } else {
                // Monitored item couldn't be created
                MonitoredItemCreateResult {
                    status_code: monitored_item.unwrap_err(),
                    monitored_item_id,
                    revised_sampling_interval: 0f64,
                    revised_queue_size: 0,
                    filter_result: ExtensionObject::null(),
                }
            };
            results.push(result);
        }
        results
    }

    /// Modify the specified monitored items, returning a result for each
    pub fn modify_monitored_items(&mut self, timestamps_to_return: TimestampsToReturn, items_to_modify: &[MonitoredItemModifyRequest]) -> Vec<MonitoredItemModifyResult> {
        let mut result = Vec::with_capacity(items_to_modify.len());
        for item_to_modify in items_to_modify {
            let monitored_item = self.monitored_items.get_mut(&item_to_modify.monitored_item_id);
            if let Some(monitored_item) = monitored_item {
                // Skip items not being reported
                if monitored_item.monitoring_mode != MonitoringMode::Reporting {
                    continue;
                }
                // Try to change the monitored item according to the modify request
                let modify_result = monitored_item.modify(timestamps_to_return, item_to_modify);
                result.push(if modify_result.is_ok() {
                    MonitoredItemModifyResult {
                        status_code: Good,
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
                    status_code: BadMonitoredItemIdInvalid,
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
        items_to_delete.iter().map(|item_to_delete| {
            // Remove the item (or report an error with the id)
            let removed = self.monitored_items.remove(item_to_delete);
            if removed.is_some() { Good } else { BadMonitoredItemIdInvalid }
        }).collect()
    }

    // Returns two vecs representing the server and client handles for each monitored item.
    // Called from the GetMonitoredItems impl
    pub fn get_handles(&self) -> (Vec<UInt32>, Vec<UInt32>) {
        let server_handles: Vec<UInt32> = self.monitored_items.values().map(|i| i.monitored_item_id).collect();
        let client_handles: Vec<UInt32> = self.monitored_items.values().map(|i| i.client_handle).collect();
        (server_handles, client_handles)
    }

    /// Checks the subscription and monitored items for state change, messages. If the tick does
    /// nothing, the function returns None. Otherwise it returns one or more messages in an Vec.
    pub fn tick(&mut self, address_space: &AddressSpace, tick_reason: TickReason, publishing_req_queued: bool, now: &DateTimeUtc) -> Option<NotificationMessage> {
        // Check if the publishing interval has elapsed. Only checks on the tick timer.
        let publishing_interval_elapsed = match tick_reason {
            TickReason::ReceivedPublishRequest => false,
            TickReason::TickTimerFired => if self.state == SubscriptionState::Creating {
                true
            } else if self.publishing_interval <= 0f64 {
                panic!("Publishing interval should have been revised to min interval")
            } else {
                // Look at the last expiration time compared to now and see if it matches
                // or exceeds the publishing interval
                let publishing_interval = time::Duration::milliseconds(self.publishing_interval as i64);
                if now.signed_duration_since(self.last_timer_expired_time) >= publishing_interval {
                    self.last_timer_expired_time = *now;
                    true
                } else {
                    false
                }
            }
        };

        // Do a tick on monitored items. Note that monitored items normally update when the interval
        // elapses but they don't have to. So this is called every tick just to catch items with their
        // own intervals.
        let (notification_message, more_notifications) = self.tick_monitored_items(address_space, now, publishing_interval_elapsed);

        // If items have changed or subscription interval elapsed then we may have notifications
        // to send or state to update
        let notifications_available = notification_message.is_some();
        let result = if notifications_available || publishing_interval_elapsed || publishing_req_queued {
            let subscription_state_params = SubscriptionStateParams {
                publishing_req_queued,
                notifications_available,
                more_notifications,
                publishing_interval_elapsed,
            };

            let update_state_result = self.update_state(tick_reason, subscription_state_params);
            trace!("subscription tick - update_state_result = {:?}", update_state_result);

            match update_state_result.update_state_action {
                UpdateStateAction::None => {
                    if notifications_available {
                        trace!("Notification message was being discarded for a do-nothing");
                    }
                    // Send nothing
                    None
                }
                UpdateStateAction::ReturnKeepAlive => {
                    if notifications_available {
                        trace!("Notification message was being discarded for a keep alive");
                    }
                    // Send a keep alive
                    Some(NotificationMessage::keep_alive(self.next_sequence_number, DateTime::from(now.clone())))
                }
                UpdateStateAction::ReturnNotifications => {
                    // Send the notification message
                    notification_message
                }
            }
        } else {
            None
        };

        // Check if the subscription interval has been exceeded since last call
        if self.lifetime_counter == 1 {
            info!("Subscription {} has expired and will be removed shortly", self.subscription_id);
            self.state = SubscriptionState::Closed;
        }

        result
    }



    /// Iterate through the monitored items belonging to the subscription, calling tick on each in turn.
    /// The function returns true if any of the monitored items due to the subscription interval
    /// elapsing, or their own interval elapsing.
    fn tick_monitored_items(&mut self, address_space: &AddressSpace, now: &DateTimeUtc, publishing_interval_elapsed: bool) -> (Option<NotificationMessage>, bool) {
        let mut monitored_item_notifications = Vec::new();
        for (_, monitored_item) in &mut self.monitored_items {
            if monitored_item.tick(address_space, now, publishing_interval_elapsed) {
                // Take all of the monitored item's pending notifications
                if let Some(mut messages) = monitored_item.all_notification_messages() {
                    monitored_item_notifications.append(&mut messages);
                }
            }
        }
        if !monitored_item_notifications.is_empty() {
            // Create a notification message and push it onto the queue
            let notification = NotificationMessage::data_change(self.next_sequence_number, DateTime::now(), monitored_item_notifications);
            let self.next_sequence_number = if self.next_sequence_number == std::u32::MAX {
                1
            } else {
                self.next_sequence_number + 1
            };
            (Some(notification), false)
        } else {
            (None, false)
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
    // * publishing_interval_elapsed - true if the publishing interval has elapsed
    //
    // Returns in order:
    //
    // * State id that handled this call. Useful for debugging which state handler triggered
    // * Update state action - none, return notifications, return keep alive
    // * Publishing request action - nothing, dequeue
    //
    pub fn update_state(&mut self, tick_reason: TickReason, p: SubscriptionStateParams) -> UpdateStateResult {
        // This function is called when a publish request is received OR the timer expired, so getting
        // both is invalid code somewhere
        if tick_reason == TickReason::ReceivedPublishRequest && p.publishing_interval_elapsed {
            panic!("Should not be possible for timer to have expired and received publish request at same time")
        }

        // Extra state debugging
        {
            use log::Level::Trace;
            if log_enabled!(Trace) {
                trace!(r#"State inputs:
    subscription_id: {} / state: {:?}
    tick_reason: {:?} / state_params: {:?}
    publishing_enabled: {}
    keep_alive_counter / lifetime_counter: {} / {}
    message_sent: {}"#,
                       self.subscription_id, self.state, tick_reason, p,
                       self.publishing_enabled,
                       self.keep_alive_counter, self.lifetime_counter, self.message_sent);
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
                return UpdateStateResult::new(HandledState::Closed1, UpdateStateAction::None);
            }
            SubscriptionState::Creating => {
                // State #2
                // CreateSubscription fails, return negative response
                // Handled in message handler
                // State #3
                self.state = SubscriptionState::Normal;
                self.message_sent = false;
                return UpdateStateResult::new(HandledState::Create3, UpdateStateAction::None);
            }
            SubscriptionState::Normal => {
                if tick_reason == TickReason::ReceivedPublishRequest {
                    if !self.publishing_enabled || (self.publishing_enabled && !p.more_notifications) {
                        // State #4
                        return UpdateStateResult::new(HandledState::Normal4, UpdateStateAction::None);
                    } else if self.publishing_enabled && p.more_notifications {
                        // State #5
                        self.reset_lifetime_counter();
                        self.message_sent = true;
                        return UpdateStateResult::new(HandledState::Normal5, UpdateStateAction::ReturnNotifications);
                    }
                } else if p.publishing_interval_elapsed {
                    if p.publishing_req_queued && self.publishing_enabled && p.notifications_available {
                        // State #6
                        self.reset_lifetime_counter();
                        self.start_publishing_timer();
                        self.message_sent = true;
                        return UpdateStateResult::new(HandledState::IntervalElapsed6, UpdateStateAction::ReturnNotifications);
                    } else if p.publishing_req_queued && !self.message_sent && (!self.publishing_enabled || (self.publishing_enabled && !p.notifications_available)) {
                        // State #7
                        self.reset_lifetime_counter();
                        self.start_publishing_timer();
                        self.message_sent = true;
                        return UpdateStateResult::new(HandledState::IntervalElapsed7, UpdateStateAction::ReturnKeepAlive);
                    } else if !p.publishing_req_queued && (!self.message_sent || (self.publishing_enabled && p.notifications_available)) {
                        // State #8
                        self.start_publishing_timer();
                        self.state = SubscriptionState::Late;
                        return UpdateStateResult::new(HandledState::IntervalElapsed8, UpdateStateAction::None);
                    } else if self.message_sent && (!self.publishing_enabled || (self.publishing_enabled && !p.notifications_available)) {
                        // State #9
                        self.start_publishing_timer();
                        self.reset_keep_alive_counter();
                        self.state = SubscriptionState::KeepAlive;
                        return UpdateStateResult::new(HandledState::IntervalElapsed9, UpdateStateAction::None);
                    }
                }
            }
            SubscriptionState::Late => {
                if tick_reason == TickReason::ReceivedPublishRequest {
                    if self.publishing_enabled && (p.notifications_available || p.more_notifications) {
                        // State #10
                        self.reset_lifetime_counter();
                        self.state = SubscriptionState::Normal;
                        self.message_sent = true;
                        return UpdateStateResult::new(HandledState::Late10, UpdateStateAction::ReturnNotifications);
                    } else if !self.publishing_enabled || (self.publishing_enabled && !p.notifications_available && !p.more_notifications) {
                        // State #11
                        self.reset_lifetime_counter();
                        self.state = SubscriptionState::KeepAlive;
                        self.message_sent = true;
                        return UpdateStateResult::new(HandledState::Late11, UpdateStateAction::ReturnKeepAlive);
                    }
                } else if p.publishing_interval_elapsed {
                    // State #12
                    self.start_publishing_timer();
                    return UpdateStateResult::new(HandledState::Late12, UpdateStateAction::None);
                }
            }
            SubscriptionState::KeepAlive => {
                if tick_reason == TickReason::ReceivedPublishRequest {
                    // State #13
                    return UpdateStateResult::new(HandledState::KeepAlive13, UpdateStateAction::None);
                } else if p.publishing_interval_elapsed {
                    if self.publishing_enabled && p.notifications_available && p.publishing_req_queued {
                        // State #14
                        self.message_sent = true;
                        self.state = SubscriptionState::Normal;
                        return UpdateStateResult::new(HandledState::KeepAlive14, UpdateStateAction::ReturnNotifications);
                    } else if p.publishing_req_queued && self.keep_alive_counter == 1 && (!self.publishing_enabled || (self.publishing_enabled && p.notifications_available)) {
                        // State #15
                        self.start_publishing_timer();
                        self.reset_keep_alive_counter();
                        return UpdateStateResult::new(HandledState::KeepAlive15, UpdateStateAction::ReturnKeepAlive);
                    } else if self.keep_alive_counter > 1 && (!self.publishing_enabled || (self.publishing_enabled && !p.notifications_available)) {
                        // State #16
                        self.start_publishing_timer();
                        self.keep_alive_counter -= 1;
                        return UpdateStateResult::new(HandledState::KeepAlive16, UpdateStateAction::None);
                    } else if !p.publishing_req_queued && (self.keep_alive_counter == 1 || (self.keep_alive_counter > 1 && self.publishing_enabled && p.notifications_available)) {
                        // State #17
                        self.start_publishing_timer();
                        self.state = SubscriptionState::Late;
                        return UpdateStateResult::new(HandledState::KeepAlive17, UpdateStateAction::None);
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

        UpdateStateResult::new(HandledState::None0, UpdateStateAction::None)
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
}