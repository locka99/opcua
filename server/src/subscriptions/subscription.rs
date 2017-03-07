use std::collections::HashMap;

use chrono;
use time;

use opcua_core::types::*;
use opcua_core::services::*;
use opcua_core::comms::*;

use subscriptions::monitored_item::*;
use address_space::*;

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
    pub publishing_interval: Duration,
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
    last_sample_time: chrono::DateTime<chrono::UTC>,
    /// State of the subscription
    state: SubscriptionState,
    /// The current subscription state
    subscription_state_variables: SubscriptionStateVariables
}

impl Subscription {
    pub fn new(subscription_id: UInt32, publishing_enabled: bool, publishing_interval: Double, lifetime_count: UInt32, keep_alive_count: UInt32, priority: Byte) -> Subscription {
        Subscription {
            subscription_id: subscription_id,
            state: SubscriptionState::Creating,
            publishing_interval: publishing_interval,
            priority: priority,
            monitored_items: HashMap::with_capacity(100),
            lifetime_count: lifetime_count,
            keep_alive_count: keep_alive_count,

            last_monitored_item_id: 0,
            last_sample_time: chrono::UTC::now(),

            // These are all subscription state variables set to their initial state
            subscription_state_variables: SubscriptionStateVariables {
                more_notifications: false,
                late_publish_request: false,
                notifications_available: false,
                lifetime_counter: lifetime_count,
                keep_alive_counter: keep_alive_count,
                message_sent: false,
                publishing_enabled: publishing_enabled,
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

        let now = chrono::UTC::now();
        for (subscription_id, subscription) in subscriptions.iter_mut() {
            // Dead subscriptions will be removed at the end
            if subscription.state == SubscriptionState::Closed {
                dead_subscriptions.push(*subscription_id);
            } else {
                let response = subscription.tick(address_space, publish_requests, &now);
                if response.is_some() {
                    result.push(response.unwrap());
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
    fn tick(&mut self, address_space: &AddressSpace, publish_requests: &Vec<PublishRequest>, now: &chrono::DateTime<chrono::UTC>) -> Option<SupportedMessage> {
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
        let items_changed = self.tick_monitored_items(address_space, &now, publishing_timer_expired);

        // If items have changed or subscription interval elapsed then we may have notifications
        // to send or state to update
        let result = if items_changed || publishing_timer_expired {
            let mut s = self.subscription_state_variables.clone();
            let result = self.update_state(&mut s, publish_requests, items_changed, publishing_timer_expired);
            self.subscription_state_variables = s;
            result
        } else {
            None
        };

        // Check if the subscription interval has been exceeded since last call
        self.subscription_state_variables.lifetime_counter += 1;
        if self.subscription_state_variables.lifetime_counter >= self.lifetime_count {
            debug! ("Subscription {} has expired and will be removed shortly", self.subscription_id);
            self.state = SubscriptionState::Closed;
            self.stop_timer();
        }

        result
    }


    /// Iterate through the monitored items belonging to the subscription, calling tick on each in turn.
    /// The function returns true if any of the monitored items due to the subscription interval
    /// elapsing, or their own interval elapsing.
    fn tick_monitored_items(&mut self, address_space: &AddressSpace, now: &chrono::DateTime<chrono::UTC>, subscription_interval_elapsed: bool) -> bool {
        let mut items_changed = false;
        for (_, monitored_item) in self.monitored_items.iter_mut() {
            if monitored_item.tick(address_space, now, subscription_interval_elapsed) {
                items_changed = true;
            }
        }
        items_changed
    }

    fn update_state(&mut self, s: &mut SubscriptionStateVariables, publish_requests: &Vec<PublishRequest>, items_changed: bool, publishing_timer_expired: bool) -> Option<SupportedMessage> {
        // Check if there is a publish request in the queue
        let receive_publish_request = !publish_requests.is_empty();

        match self.state {
            SubscriptionState::Closed => {},
            SubscriptionState::Creating => {
                self.state = SubscriptionState::Normal;
                s.message_sent = false;
                return None;
            },
            SubscriptionState::Normal => {
                if receive_publish_request && !s.publishing_enabled || (s.publishing_enabled && !s.more_notifications) {
                    // State #4
                    self.delete_acked_notification_msgs();
                    self.enqueue_publishing_request();
                } else if receive_publish_request && s.publishing_enabled && s.more_notifications {
                    // State #5
                    self.reset_lifetime_counter();
                    self.delete_acked_notification_msgs();
                    s.message_sent = true;
                    return self.return_notifications();
                } else if publishing_timer_expired && s.publishing_req_queued && s.publishing_enabled && s.notifications_available {
                    // State #6
                    self.reset_lifetime_counter();
                    self.start_publishing_timer();
                    self.dequeue_publish_request();
                    s.message_sent = true;
                    return self.return_notifications();
                } else if publishing_timer_expired && s.publishing_req_queued && !s.message_sent && (!s.publishing_enabled || (s.publishing_enabled && !s.notifications_available)) {
                    // State #7
                    self.reset_lifetime_counter();
                    self.start_publishing_timer();
                    self.dequeue_publish_request();
                    s.message_sent = true;
                    return self.return_keep_alive();
                } else if publishing_timer_expired && !s.publishing_req_queued && (!s.message_sent || (s.publishing_enabled && s.notifications_available)) {
                    // State #8
                    self.start_publishing_timer();
                    self.state = SubscriptionState::Late;
                    return None;
                } else if publishing_timer_expired && s.message_sent && (!s.publishing_enabled || (s.publishing_enabled && !s.notifications_available)) {
                    // State #9
                    self.start_publishing_timer();
                    self.reset_keep_alive_counter();
                    self.state = SubscriptionState::KeepAlive;
                    return None;
                }
            },
            SubscriptionState::Late => {
                if receive_publish_request && s.publishing_enabled && (s.notifications_available || s.more_notifications) {
                    // State #10
                    self.reset_lifetime_counter();
                    self.delete_acked_notification_msgs();
                    self.state = SubscriptionState::Normal;
                    s.message_sent = true;
                    return self.return_notifications();
                } else if receive_publish_request && (!s.publishing_enabled || (s.publishing_enabled && !s.notifications_available && !s.more_notifications)) {
                    // State #11
                    self.reset_lifetime_counter();
                    self.delete_acked_notification_msgs();
                    self.return_keep_alive();
                    self.state = SubscriptionState::KeepAlive;
                    s.message_sent = true;
                    return None;
                } else if publishing_timer_expired {
                    // State #12
                    self.start_publishing_timer();
                    return None;
                }
            },
            SubscriptionState::KeepAlive => {
                if receive_publish_request {
                    // State #13
                    self.delete_acked_notification_msgs();
                    self.enqueue_publishing_request();
                } else if publishing_timer_expired && s.publishing_enabled && s.notifications_available && s.publishing_req_queued {
                    // State #14
                    self.dequeue_publish_request();
                    s.message_sent = true;
                    self.state = SubscriptionState::Normal;
                    return self.return_notifications();
                } else if publishing_timer_expired && s.publishing_req_queued && s.keep_alive_counter == 1 &&
                    !s.publishing_enabled || (s.publishing_enabled && s.notifications_available) {
                    // State #15
                    self.start_publishing_timer();
                    self.dequeue_publish_request();
                    self.reset_keep_alive_counter();
                    return self.return_keep_alive();
                } else if publishing_timer_expired && s.keep_alive_counter > 1 && (!s.publishing_enabled || (s.publishing_enabled && !s.notifications_available)) {
                    // State #16
                    self.start_publishing_timer();
                    s.keep_alive_counter -= 1
                } else if publishing_timer_expired && !s.publishing_req_queued && (s.keep_alive_counter == 1 || (s.keep_alive_counter > 1 && s.publishing_enabled && s.notifications_available)) {
                    // State #17
                    self.start_publishing_timer();
                    self.state = SubscriptionState::Late;
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


        None
    }

    pub fn delete_acked_notification_msgs(&mut self) {}


    /// De-queue a publishing request in first-in first-out order.
    /// Validate if the publish request is still valid by checking the timeoutHint in the
    /// RequestHeader. If the request timed out, send a Bad_Timeout service result for the request
    /// and de-queue another publish request.
    pub fn dequeue_publish_request(&mut self) {
        // TODO
    }

    /// Enqueue the publishing request
    pub fn enqueue_publishing_request(&mut self) {
        // TODO wtf does this mean
    }

    /// Reset the keep-alive counter to the maximum keep-alive count of the Subscription.
    /// The maximum keep-alive count is set by the Client when the Subscription is created
    /// and may be modified using the ModifySubscription Service
    pub fn reset_keep_alive_counter(&mut self) {
        self.subscription_state_variables.keep_alive_counter = self.keep_alive_count;
    }

    /// Reset the lifetime counter to the value specified for the life time of the subscription
    /// in the create subscription service
    pub fn reset_lifetime_counter(&mut self) {
        self.subscription_state_variables.lifetime_counter = self.lifetime_count;
    }

    /// Start or restart the publishing timer and decrement the LifetimeCounter Variable.
    pub fn start_publishing_timer(&mut self) {
        self.subscription_state_variables.lifetime_counter -= 1;
    }

    /// CreateKeepAliveMsg()
    /// ReturnResponse()
    pub fn return_keep_alive(&mut self) -> Option<SupportedMessage> {
        // TODO keep alive message
        None
    }

    /// CreateNotificationMsg()
    /// ReturnResponse()
    /// If (MoreNotifications == TRUE) && (PublishingReqQueued == TRUE)
    /// {
    ///   DequeuePublishReq()
    ///   Loop through this function again
    /// }
    pub fn return_notifications(&mut self) -> Option<SupportedMessage> {
        // TODO notification messages
        None
    }

    /// Return the appropriate response setting the parameter values and status codes
    /// for the value
    pub fn return_response() -> Option<SupportedMessage> {
        // TODO probably remove this fn
        None
    }


    //////////////////////////////////////////////

    pub fn send_publish_response(&mut self, request: &PublishRequest) -> PublishResponse {
        let service_status = &GOOD;

        let response_header = ResponseHeader::new_service_result(&DateTime::now(), &request.request_header, service_status);

        let available_sequence_numbers = None;
        let more_notifications = false;

        let sequence_number = 0;
        let publish_time = DateTime::now();
        let notification_data = Some(vec![]);

        let notification_message = NotificationMessage {
            sequence_number: sequence_number,
            publish_time: publish_time,
            notification_data: notification_data,
        };
        let results = None;
        let diagnostic_infos = None;

        PublishResponse {
            response_header: response_header,
            subscription_id: self.subscription_id,
            available_sequence_numbers: available_sequence_numbers,
            more_notifications: more_notifications,
            notification_message: notification_message,
            results: results,
            diagnostic_infos: diagnostic_infos,
        }
    }
}