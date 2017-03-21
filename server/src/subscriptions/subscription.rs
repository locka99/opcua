use std::collections::HashMap;

use chrono;
use time;

use opcua_core::types::*;
use opcua_core::services::*;
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
    // Outgoing notifications in a map by sequence number
    pub notifications: HashMap<UInt32, NotificationMessage>,
    // The last monitored item id
    last_monitored_item_id: UInt32,
    // The time that the subscription interval last fired
    last_sample_time: DateTimeUTC,
    /// The value that records the value of the sequence number used in NotificationMessages.
    last_sequence_number: UInt32,
}

const DEFAULT_MONITORED_ITEM_CAPACITY: usize = 100;
const DEFAULT_NOTIFICATIONS_CAPACITY: usize = 100;

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
            notifications: HashMap::with_capacity(DEFAULT_NOTIFICATIONS_CAPACITY),
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

    // modify_monitored_items
    // delete_monitored_items

    /// Iterate all subscriptions calling tick on each. Note this could potentially be done to run in parallel
    /// assuming the action to clean dead subscriptions was a join done after all ticks had completed.
    pub fn tick_subscriptions(address_space: &AddressSpace, publish_requests: &Vec<PublishRequest>, subscriptions: &mut HashMap<UInt32, Subscription>) -> Option<Vec<SupportedMessage>> {
        let mut dead_subscriptions: Vec<u32> = Vec::with_capacity(5);

        let mut result = Vec::new();

        // TODO remove this
        let mut publish_requests = publish_requests.clone();

        let now = chrono::UTC::now();
        for (subscription_id, subscription) in subscriptions.iter_mut() {
            // Dead subscriptions will be removed at the end
            if subscription.state == SubscriptionState::Closed {
                dead_subscriptions.push(*subscription_id);
            } else {
                if let Some(notification_message) = subscription.tick(address_space, &mut publish_requests, &now) {
                    let publish_response = PublishResponse {
                        response_header: ResponseHeader::new_notification_response(&DateTime::now(), &GOOD),
                        subscription_id: *subscription_id,
                        available_sequence_numbers: None,
                        // TODO
                        more_notifications: subscription.more_notifications,
                        notification_message: notification_message,
                        results: None,
                        // TODO
                        diagnostic_infos: None,
                    };
                    result.push(SupportedMessage::PublishResponse(publish_response));
                }
            }
        }
        // Remove dead subscriptions
        for subscription_id in dead_subscriptions {
            subscriptions.remove(&subscription_id);
        }

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    /// Checks the subscription and monitored items for state change, messages. If the tick does
    /// nothing, the function returns None. Otherwise it returns one or more messages in an Vec.
    fn tick(&mut self, address_space: &AddressSpace, publish_requests: &mut Vec<PublishRequest>, now: &DateTimeUTC) -> Option<NotificationMessage> {
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
            let (_, result) = self.update_state(publish_requests, publishing_timer_expired);
            match result {
                UpdateStateAction::None => None,
                UpdateStateAction::ReturnKeepAlive => self.return_keep_alive(),
                UpdateStateAction::ReturnNotifications => self.return_notifications(),
            }
        } else {
            None
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

    // Update the state of the subscription, returning a tuple containing the state that handled
    // the update and optionally any notifications. The publish requests is mutable because
    // a request may be dequeued and potentially requeued according to the handler.
    pub fn update_state(&mut self, publish_requests: &mut Vec<PublishRequest>, publishing_timer_expired: bool) -> (u8, UpdateStateAction) {
        // Check if there is a publish request in the queue
        let receive_publish_request: Option<PublishRequest> = publish_requests.pop();

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
                return (1, UpdateStateAction::None);
            },
            SubscriptionState::Creating => {
                // State #2
                // CreateSubscription fails, return negative response
                // Handled in message handler

                // State #3
                self.state = SubscriptionState::Normal;
                self.message_sent = false;
                return (3, UpdateStateAction::None);
            },
            SubscriptionState::Normal => {
                if receive_publish_request.is_some() && !self.publishing_enabled || (self.publishing_enabled && !self.more_notifications) {
                    // State #4
                    let receive_publish_request = receive_publish_request.unwrap();
                    self.delete_acked_notification_msgs(&receive_publish_request);
                    publish_requests.push(receive_publish_request); // enqueue_publishing_request
                    return (4, UpdateStateAction::None);
                } else if receive_publish_request.is_some() && self.publishing_enabled && self.more_notifications {
                    // State #5
                    self.reset_lifetime_counter();
                    self.delete_acked_notification_msgs(receive_publish_request.as_ref().unwrap());
                    self.message_sent = true;
                    return (5, UpdateStateAction::ReturnNotifications);
                } else if publishing_timer_expired && self.publishing_req_queued && self.publishing_enabled && self.notifications_available {
                    // State #6
                    self.reset_lifetime_counter();
                    self.start_publishing_timer();
                    self.dequeue_publish_request(publish_requests);
                    self.message_sent = true;
                    return (6, UpdateStateAction::ReturnNotifications);
                } else if publishing_timer_expired && self.publishing_req_queued && !self.message_sent && (!self.publishing_enabled || (self.publishing_enabled && !self.notifications_available)) {
                    // State #7
                    self.reset_lifetime_counter();
                    self.start_publishing_timer();
                    self.dequeue_publish_request(publish_requests);
                    self.message_sent = true;
                    return (7, UpdateStateAction::ReturnKeepAlive);
                } else if publishing_timer_expired && !self.publishing_req_queued && (!self.message_sent || (self.publishing_enabled && self.notifications_available)) {
                    // State #8
                    self.start_publishing_timer();
                    self.state = SubscriptionState::Late;
                    return (8, UpdateStateAction::None);
                } else if publishing_timer_expired && self.message_sent && (!self.publishing_enabled || (self.publishing_enabled && !self.notifications_available)) {
                    // State #9
                    self.start_publishing_timer();
                    self.reset_keep_alive_counter();
                    self.state = SubscriptionState::KeepAlive;
                    return (9, UpdateStateAction::None);
                }
            },
            SubscriptionState::Late => {
                if receive_publish_request.is_some() && self.publishing_enabled && (self.notifications_available || self.more_notifications) {
                    // State #10
                    self.reset_lifetime_counter();
                    self.delete_acked_notification_msgs(receive_publish_request.as_ref().unwrap());
                    self.state = SubscriptionState::Normal;
                    self.message_sent = true;
                    return (10, UpdateStateAction::ReturnNotifications);
                } else if receive_publish_request.is_some() && (!self.publishing_enabled || (self.publishing_enabled && !self.notifications_available && !self.more_notifications)) {
                    // State #11
                    self.reset_lifetime_counter();
                    self.delete_acked_notification_msgs(receive_publish_request.as_ref().unwrap());
                    self.state = SubscriptionState::KeepAlive;
                    self.message_sent = true;
                    return (11, UpdateStateAction::ReturnKeepAlive);
                } else if publishing_timer_expired {
                    // State #12
                    self.start_publishing_timer();
                    return (12, UpdateStateAction::None);
                }
            },
            SubscriptionState::KeepAlive => {
                if receive_publish_request.is_some() {
                    // State #13
                    let receive_publish_request = receive_publish_request.unwrap();
                    self.delete_acked_notification_msgs(&receive_publish_request);
                    publish_requests.push(receive_publish_request); // enqueue_publishing_request
                    return (13, UpdateStateAction::None);
                } else if publishing_timer_expired && self.publishing_enabled && self.notifications_available && self.publishing_req_queued {
                    // State #14
                    self.dequeue_publish_request(publish_requests);
                    self.message_sent = true;
                    self.state = SubscriptionState::Normal;
                    return (14, UpdateStateAction::ReturnNotifications);
                } else if publishing_timer_expired && self.publishing_req_queued && self.keep_alive_counter == 1 &&
                    !self.publishing_enabled || (self.publishing_enabled && self.notifications_available) {
                    // State #15
                    self.start_publishing_timer();
                    self.dequeue_publish_request(publish_requests);
                    self.reset_keep_alive_counter();
                    return (15, UpdateStateAction::ReturnKeepAlive);
                } else if publishing_timer_expired && self.keep_alive_counter > 1 && (!self.publishing_enabled || (self.publishing_enabled && !self.notifications_available)) {
                    // State #16
                    self.start_publishing_timer();
                    self.keep_alive_counter -= 1;
                    return (16, UpdateStateAction::None);
                } else if publishing_timer_expired && !self.publishing_req_queued && (self.keep_alive_counter == 1 || (self.keep_alive_counter > 1 && self.publishing_enabled && self.notifications_available)) {
                    // State #17
                    self.start_publishing_timer();
                    self.state = SubscriptionState::Late;
                    return (17, UpdateStateAction::None);
                }
            },
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

        (0, UpdateStateAction::None)
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

    /// De-queue a publishing request in first-in first-out order.
    /// Validate if the publish request is still valid by checking the timeoutHint in the
    /// RequestHeader. If the request timed out, send a BAD_TIMEOUT service result for the request
    /// and de-queue another publish request.
    ///
    /// The implementation will dequeue a PublishRequest if there is one and it is valid. If there
    /// is no request then it will return None. If there is a request but it has timed out it will return
    /// a PublishResponse with a timeout service result
    pub fn dequeue_publish_request(&mut self, request_queue: &mut Vec<PublishRequest>) -> Result<PublishRequest, Option<PublishResponse>> {
        if request_queue.is_empty() {
            Err(None)
        } else {
            Ok(request_queue.pop().unwrap())
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
    pub fn return_keep_alive(&mut self) -> Option<NotificationMessage> {
        // TODO keep alive message
        None
    }

    pub fn return_notifications(&mut self) -> Option<NotificationMessage> {
        /// CreateNotificationMsg()
        /// ReturnResponse()
        /// If (MoreNotifications == TRUE) && (PublishingReqQueued == TRUE)
        /// {
        ///   DequeuePublishReq()
        ///   Loop through this function again
        /// }
        None
    }
}