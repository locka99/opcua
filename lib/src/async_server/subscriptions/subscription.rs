use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

use crate::{
    core::handle::Handle,
    server::prelude::{DataValue, DateTime, DateTimeUtc, NotificationMessage, StatusCode},
};

use super::monitored_item::{MonitoredItem, Notification};

#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum SubscriptionState {
    Closed,
    Creating,
    Normal,
    Late,
    KeepAlive,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct MonitoredItemHandle {
    pub subscription_id: u32,
    pub monitored_item_id: u32,
}

#[derive(Debug)]
pub(crate) struct SubscriptionStateParams {
    pub notifications_available: bool,
    pub more_notifications: bool,
    pub publishing_req_queued: bool,
    pub publishing_timer_expired: bool,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum UpdateStateAction {
    None,
    // Return a keep alive
    ReturnKeepAlive,
    // Return notifications
    ReturnNotifications,
    // The subscription was created normally
    SubscriptionCreated,
    // The subscription has expired and must be closed
    SubscriptionExpired,
}

/// This is for debugging purposes. It allows the caller to validate the output state if required.
///
/// Values correspond to state table in OPC UA Part 4 5.13.1.2
///
#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum HandledState {
    None0 = 0,
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
    Closed27 = 27,
}

/// This is for debugging purposes. It allows the caller to validate the output state if required.
#[derive(Debug)]
pub(crate) struct UpdateStateResult {
    #[allow(unused)]
    pub handled_state: HandledState,
    pub update_state_action: UpdateStateAction,
}

impl UpdateStateResult {
    pub fn new(
        handled_state: HandledState,
        update_state_action: UpdateStateAction,
    ) -> UpdateStateResult {
        UpdateStateResult {
            handled_state,
            update_state_action,
        }
    }
}

#[derive(Debug)]
pub struct Subscription {
    id: u32,
    publishing_interval: Duration,
    max_lifetime_counter: u32,
    max_keep_alive_counter: u32,
    priority: u8,
    monitored_items: HashMap<u32, MonitoredItem>,
    /// Monitored items that have seen notifications.
    notified_monitored_items: HashSet<u32>,
    /// State of the subscription
    state: SubscriptionState,
    /// A value that contains the number of consecutive publishing timer expirations without Client
    /// activity before the Subscription is terminated.
    lifetime_counter: u32,
    /// Keep alive counter decrements when there are no notifications to publish and when it expires
    /// requests to send an empty notification as a keep alive event
    keep_alive_counter: u32,
    /// boolean value that is set to true to mean that either a NotificationMessage or a keep-alive
    /// Message has been sent on the Subscription. It is a flag that is used to ensure that either
    /// a NotificationMessage or a keep-alive Message is sent out the first time the publishing timer
    /// expires.
    first_message_sent: bool,
    /// The parameter that requests publishing to be enabled or disabled.
    publishing_enabled: bool,
    /// A flag that tells the subscription to send the latest value of every monitored item on the
    /// next publish request.
    resend_data: bool,
    /// The next sequence number to be sent
    sequence_number: Handle,
    /// Last notification's sequence number. This is a sanity check since sequence numbers should start from
    /// 1 and be sequential - it that doesn't happen the server will panic because something went
    /// wrong somewhere.
    last_sequence_number: u32,
    // The time that the subscription interval last fired
    last_time_publishing_interval_elapsed: Instant,
    // Currently outstanding notifications to send
    notifications: VecDeque<NotificationMessage>,
    /// Maximum number of queued notifications.
    max_queued_notifications: usize,
    /// Maximum number of notifications per publish.
    max_notifications_per_publish: usize,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum TickReason {
    ReceivePublishRequest,
    TickTimerFired,
}

impl Subscription {
    pub fn new(
        id: u32,
        publishing_enabled: bool,
        publishing_interval: Duration,
        lifetime_counter: u32,
        keep_alive_counter: u32,
        priority: u8,
        max_queued_notifications: usize,
        max_notifications_per_publish: usize,
    ) -> Self {
        Self {
            id,
            publishing_interval,
            max_lifetime_counter: lifetime_counter,
            max_keep_alive_counter: keep_alive_counter,
            priority,
            monitored_items: HashMap::new(),
            notified_monitored_items: HashSet::new(),
            // State variables
            state: SubscriptionState::Creating,
            lifetime_counter,
            keep_alive_counter,
            first_message_sent: false,
            resend_data: false,
            publishing_enabled,
            // Counters for new items
            sequence_number: Handle::new(1),
            last_sequence_number: 0,
            last_time_publishing_interval_elapsed: Instant::now(),
            notifications: VecDeque::new(),
            max_queued_notifications,
            max_notifications_per_publish,
        }
    }

    pub fn len(&self) -> usize {
        self.monitored_items.len()
    }

    pub fn get_mut(&mut self, id: &u32) -> Option<&mut MonitoredItem> {
        self.monitored_items.get_mut(id)
    }

    pub fn contains_key(&self, id: &u32) -> bool {
        self.monitored_items.contains_key(id)
    }

    pub fn drain<'a>(&'a mut self) -> impl Iterator<Item = (u32, MonitoredItem)> + 'a {
        self.monitored_items.drain()
    }

    pub fn set_resend_data(&mut self) {
        self.resend_data = true;
    }

    pub fn remove(&mut self, id: &u32) -> Option<MonitoredItem> {
        self.monitored_items.remove(id)
    }

    pub fn insert(&mut self, id: u32, item: MonitoredItem) {
        self.monitored_items.insert(id, item);
        self.notified_monitored_items.insert(id);
    }

    pub fn notify_data_value(&mut self, id: &u32, value: DataValue) {
        if let Some(item) = self.monitored_items.get_mut(id) {
            if item.notify_data_value(value) {
                self.notified_monitored_items.insert(*id);
            }
        }
    }

    /// Tests if the publishing interval has elapsed since the last time this function in which case
    /// it returns `true` and updates its internal state.
    fn test_and_set_publishing_interval_elapsed(&mut self, now: Instant) -> bool {
        // Look at the last expiration time compared to now and see if it matches
        // or exceeds the publishing interval
        let elapsed = now - self.last_time_publishing_interval_elapsed;
        if elapsed >= self.publishing_interval {
            self.last_time_publishing_interval_elapsed = now;
            true
        } else {
            false
        }
    }

    pub(crate) fn tick(
        &mut self,
        now: &DateTimeUtc,
        now_instant: Instant,
        tick_reason: TickReason,
        publishing_req_queued: bool,
        max_notifications: usize,
    ) {
        let publishing_interval_elapsed = match tick_reason {
            TickReason::ReceivePublishRequest => false,
            TickReason::TickTimerFired => {
                if self.state == SubscriptionState::Creating {
                    true
                } else {
                    self.test_and_set_publishing_interval_elapsed(now_instant)
                }
            }
        };

        let messages = match self.state {
            SubscriptionState::Closed | SubscriptionState::Creating => Vec::new(),
            _ if !publishing_interval_elapsed => Vec::new(),
            _ => {
                let resend_data = std::mem::take(&mut self.resend_data);
                self.tick_monitored_items(now, resend_data, max_notifications)
            }
        };

        let notifications_available = !self.notifications.is_empty() || !messages.is_empty();
        let more_notifications = self.notifications.len() > 1;

        // If items have changed or subscription interval elapsed then we may have notifications
        // to send or state to update
        if notifications_available || publishing_interval_elapsed || publishing_req_queued {
            // Update the internal state of the subscription based on what happened
            let update_state_result = self.update_state(
                tick_reason,
                SubscriptionStateParams {
                    publishing_req_queued,
                    notifications_available,
                    more_notifications,
                    publishing_timer_expired: publishing_interval_elapsed,
                },
            );
            trace!(
                "subscription tick - update_state_result = {:?}",
                update_state_result
            );
            self.handle_state_result(now, update_state_result, messages);
        }
    }

    fn enqueue_notification(&mut self, notification: NotificationMessage) {
        // For sanity, check the sequence number is the expected sequence number.
        let expected_sequence_number = if self.last_sequence_number == u32::MAX {
            1
        } else {
            self.last_sequence_number + 1
        };
        if notification.sequence_number != expected_sequence_number {
            panic!(
                "Notification's sequence number is not sequential, expecting {}, got {}",
                expected_sequence_number, notification.sequence_number
            );
        }
        if self.notifications.len() >= self.max_queued_notifications {
            warn!("Maximum number of queued notifications exceeded, dropping oldest. Subscription ID: {}", self.id);
            self.notifications.pop_front();
        }

        // debug!("Enqueuing notification {:?}", notification);
        self.last_sequence_number = notification.sequence_number;
        self.notifications.push_back(notification);
    }

    pub(super) fn take_notification(&mut self) -> Option<NotificationMessage> {
        self.notifications.pop_front()
    }

    pub(super) fn more_notifications(&self) -> bool {
        !self.notifications.is_empty()
    }

    pub(super) fn ready_to_remove(&self) -> bool {
        self.state == SubscriptionState::Closed && self.notifications.is_empty()
    }

    fn handle_state_result(
        &mut self,
        now: &DateTimeUtc,
        update_state_result: UpdateStateResult,
        messages: Vec<NotificationMessage>,
    ) {
        // Now act on the state's action
        match update_state_result.update_state_action {
            UpdateStateAction::None => {
                if let Some(notification) = messages.first() {
                    // Reset the next sequence number to the discarded notification
                    let notification_sequence_number = notification.sequence_number;
                    self.sequence_number.set_next(notification_sequence_number);
                    debug!("Notification message nr {} was being ignored for a do-nothing, update state was {:?}", notification_sequence_number, update_state_result);
                }
                // Send nothing
            }
            UpdateStateAction::ReturnKeepAlive => {
                if let Some(notification) = messages.first() {
                    // Reset the next sequence number to the discarded notification
                    let notification_sequence_number = notification.sequence_number;
                    self.sequence_number.set_next(notification_sequence_number);
                    debug!("Notification message nr {} was being ignored for a keep alive, update state was {:?}", notification_sequence_number, update_state_result);
                }
                // Send a keep alive
                debug!("Sending keep alive response");
                let notification = NotificationMessage::keep_alive(
                    self.sequence_number.next(),
                    DateTime::from(*now),
                );
                self.enqueue_notification(notification);
            }
            UpdateStateAction::ReturnNotifications => {
                // Add the notification message to the queue
                for notif in messages {
                    self.enqueue_notification(notif);
                }
            }
            UpdateStateAction::SubscriptionCreated => {
                if !messages.is_empty() {
                    panic!("SubscriptionCreated got a notification");
                }
                // Subscription was created successfully
                //                let notification = NotificationMessage::status_change(self.sequence_number.next(), DateTime::from(now.clone()), StatusCode::Good);
                //                self.enqueue_notification(notification);
            }
            UpdateStateAction::SubscriptionExpired => {
                if !messages.is_empty() {
                    panic!("SubscriptionExpired got a notification");
                }
                // Delete the monitored items, issue a status change for the subscription
                debug!("Subscription status change to closed / timeout");
                self.monitored_items.clear();
                let notification = NotificationMessage::status_change(
                    self.sequence_number.next(),
                    DateTime::from(*now),
                    StatusCode::BadTimeout,
                );
                self.enqueue_notification(notification);
            }
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
    pub(crate) fn update_state(
        &mut self,
        tick_reason: TickReason,
        p: SubscriptionStateParams,
    ) -> UpdateStateResult {
        // This function is called when a publish request is received OR the timer expired, so getting
        // both is invalid code somewhere
        if tick_reason == TickReason::ReceivePublishRequest && p.publishing_timer_expired {
            panic!("Should not be possible for timer to have expired and received publish request at same time")
        }

        // Extra state debugging
        {
            use log::Level::Trace;
            if log_enabled!(Trace) {
                trace!(
                    r#"State inputs:
    subscription_id: {} / state: {:?}
    tick_reason: {:?} / state_params: {:?}
    publishing_enabled: {}
    keep_alive_counter / lifetime_counter: {} / {}
    message_sent: {}"#,
                    self.id,
                    self.state,
                    tick_reason,
                    p,
                    self.publishing_enabled,
                    self.keep_alive_counter,
                    self.lifetime_counter,
                    self.first_message_sent
                );
            }
        }

        // This is a state engine derived from OPC UA Part 4 Publish service and might look a
        // little odd for that.
        //
        // Note in some cases, some of the actions have already happened outside of this function.
        // For example, publish requests are already queued before we come in here and this function
        // uses what its given. Likewise, this function does not "send" notifications, rather
        // it returns them (if any) and it is up to the caller to send them

        // more state tests that match on more than one state
        match self.state {
            SubscriptionState::Normal | SubscriptionState::Late | SubscriptionState::KeepAlive => {
                if self.lifetime_counter == 1 {
                    // State #27
                    self.state = SubscriptionState::Closed;
                    return UpdateStateResult::new(
                        HandledState::Closed27,
                        UpdateStateAction::SubscriptionExpired,
                    );
                }
            }
            _ => {
                // DO NOTHING
            }
        }

        match self.state {
            SubscriptionState::Creating => {
                // State #2
                // CreateSubscription fails, return negative response
                // Handled in message handler
                // State #3
                self.state = SubscriptionState::Normal;
                self.first_message_sent = false;
                return UpdateStateResult::new(
                    HandledState::Create3,
                    UpdateStateAction::SubscriptionCreated,
                );
            }
            SubscriptionState::Normal => {
                if tick_reason == TickReason::ReceivePublishRequest
                    && (!self.publishing_enabled
                        || (self.publishing_enabled && !p.more_notifications))
                {
                    // State #4
                    return UpdateStateResult::new(HandledState::Normal4, UpdateStateAction::None);
                } else if tick_reason == TickReason::ReceivePublishRequest
                    && self.publishing_enabled
                    && p.more_notifications
                {
                    // State #5
                    self.reset_lifetime_counter();
                    self.first_message_sent = true;
                    return UpdateStateResult::new(
                        HandledState::Normal5,
                        UpdateStateAction::ReturnNotifications,
                    );
                } else if p.publishing_timer_expired
                    && p.publishing_req_queued
                    && self.publishing_enabled
                    && p.notifications_available
                {
                    // State #6
                    self.reset_lifetime_counter();
                    self.start_publishing_timer();
                    self.first_message_sent = true;
                    return UpdateStateResult::new(
                        HandledState::IntervalElapsed6,
                        UpdateStateAction::ReturnNotifications,
                    );
                } else if p.publishing_timer_expired
                    && p.publishing_req_queued
                    && !self.first_message_sent
                    && (!self.publishing_enabled
                        || (self.publishing_enabled && !p.notifications_available))
                {
                    // State #7
                    self.reset_lifetime_counter();
                    self.start_publishing_timer();
                    self.first_message_sent = true;
                    return UpdateStateResult::new(
                        HandledState::IntervalElapsed7,
                        UpdateStateAction::ReturnKeepAlive,
                    );
                } else if p.publishing_timer_expired
                    && !p.publishing_req_queued
                    && (!self.first_message_sent
                        || (self.publishing_enabled && p.notifications_available))
                {
                    // State #8
                    self.start_publishing_timer();
                    self.state = SubscriptionState::Late;
                    return UpdateStateResult::new(
                        HandledState::IntervalElapsed8,
                        UpdateStateAction::None,
                    );
                } else if p.publishing_timer_expired
                    && self.first_message_sent
                    && (!self.publishing_enabled
                        || (self.publishing_enabled && !p.notifications_available))
                {
                    // State #9
                    self.start_publishing_timer();
                    self.reset_keep_alive_counter();
                    self.state = SubscriptionState::KeepAlive;
                    return UpdateStateResult::new(
                        HandledState::IntervalElapsed9,
                        UpdateStateAction::None,
                    );
                }
            }
            SubscriptionState::Late => {
                if tick_reason == TickReason::ReceivePublishRequest
                    && self.publishing_enabled
                    && (p.notifications_available || p.more_notifications)
                {
                    // State #10
                    self.reset_lifetime_counter();
                    self.state = SubscriptionState::Normal;
                    self.first_message_sent = true;
                    return UpdateStateResult::new(
                        HandledState::Late10,
                        UpdateStateAction::ReturnNotifications,
                    );
                } else if tick_reason == TickReason::ReceivePublishRequest
                    && (!self.publishing_enabled
                        || (self.publishing_enabled
                            && !p.notifications_available
                            && !p.more_notifications))
                {
                    // State #11
                    self.reset_lifetime_counter();
                    self.state = SubscriptionState::KeepAlive;
                    self.first_message_sent = true;
                    return UpdateStateResult::new(
                        HandledState::Late11,
                        UpdateStateAction::ReturnKeepAlive,
                    );
                } else if p.publishing_timer_expired {
                    // State #12
                    self.start_publishing_timer();
                    return UpdateStateResult::new(HandledState::Late12, UpdateStateAction::None);
                }
            }
            SubscriptionState::KeepAlive => {
                if tick_reason == TickReason::ReceivePublishRequest {
                    // State #13
                    return UpdateStateResult::new(
                        HandledState::KeepAlive13,
                        UpdateStateAction::None,
                    );
                } else if p.publishing_timer_expired
                    && self.publishing_enabled
                    && p.notifications_available
                    && p.publishing_req_queued
                {
                    // State #14
                    self.first_message_sent = true;
                    self.state = SubscriptionState::Normal;
                    return UpdateStateResult::new(
                        HandledState::KeepAlive14,
                        UpdateStateAction::ReturnNotifications,
                    );
                } else if p.publishing_timer_expired
                    && p.publishing_req_queued
                    && self.keep_alive_counter == 1
                    && (!self.publishing_enabled
                        || (self.publishing_enabled && p.notifications_available))
                {
                    // State #15
                    self.start_publishing_timer();
                    self.reset_keep_alive_counter();
                    return UpdateStateResult::new(
                        HandledState::KeepAlive15,
                        UpdateStateAction::ReturnKeepAlive,
                    );
                } else if p.publishing_timer_expired
                    && self.keep_alive_counter > 1
                    && (!self.publishing_enabled
                        || (self.publishing_enabled && !p.notifications_available))
                {
                    // State #16
                    self.start_publishing_timer();
                    self.keep_alive_counter -= 1;
                    return UpdateStateResult::new(
                        HandledState::KeepAlive16,
                        UpdateStateAction::None,
                    );
                } else if p.publishing_timer_expired
                    && !p.publishing_req_queued
                    && (self.keep_alive_counter == 1
                        || (self.keep_alive_counter > 1
                            && self.publishing_enabled
                            && p.notifications_available))
                {
                    // State #17
                    self.start_publishing_timer();
                    self.state = SubscriptionState::Late;
                    return UpdateStateResult::new(
                        HandledState::KeepAlive17,
                        UpdateStateAction::None,
                    );
                }
            }
            _ => {
                // DO NOTHING
            }
        }

        UpdateStateResult::new(HandledState::None0, UpdateStateAction::None)
    }

    fn handle_triggers(
        &mut self,
        now: &DateTimeUtc,
        triggers: Vec<(u32, u32)>,
        notifications: &mut Vec<Notification>,
        max_notifications: usize,
        messages: &mut Vec<NotificationMessage>,
    ) {
        for (triggering_item, item_id) in triggers {
            let Some(item) = self.monitored_items.get_mut(&item_id) else {
                if let Some(item) = self.monitored_items.get_mut(&triggering_item) {
                    item.remove_dead_trigger(item_id);
                }
                continue;
            };

            while let Some(notif) = item.pop_notification() {
                notifications.push(notif);
                if notifications.len() >= max_notifications && max_notifications > 0 {
                    messages.push(Self::make_notification_message(
                        self.sequence_number.next(),
                        std::mem::take(notifications),
                        now,
                    ));
                }
            }
        }
    }

    fn make_notification_message(
        next_sequence_number: u32,
        notifications: Vec<Notification>,
        now: &DateTimeUtc,
    ) -> NotificationMessage {
        let mut data_change_notifications = Vec::new();
        let mut event_notifications = Vec::new();

        for notif in notifications {
            match notif {
                Notification::MonitoredItemNotification(n) => data_change_notifications.push(n),
                Notification::Event(n) => event_notifications.push(n),
            }
        }

        NotificationMessage::data_change(
            next_sequence_number,
            DateTime::from(*now),
            data_change_notifications,
            event_notifications,
        )
    }

    fn tick_monitored_item(
        monitored_item: &mut MonitoredItem,
        now: &DateTimeUtc,
        resend_data: bool,
        max_notifications: usize,
        triggers: &mut Vec<(u32, u32)>,
        notifications: &mut Vec<Notification>,
        messages: &mut Vec<NotificationMessage>,
        sequence_numbers: &mut Handle,
    ) {
        if monitored_item.is_sampling() && monitored_item.has_new_notifications() {
            triggers.extend(
                monitored_item
                    .triggered_items()
                    .iter()
                    .copied()
                    .map(|id| (monitored_item.id(), id)),
            );
        }

        if monitored_item.is_reporting() {
            if resend_data {
                monitored_item.add_current_value_to_queue();
            }
            if monitored_item.has_notifications() {
                while let Some(notif) = monitored_item.pop_notification() {
                    notifications.push(notif);
                    if notifications.len() >= max_notifications && max_notifications > 0 {
                        messages.push(Self::make_notification_message(
                            sequence_numbers.next(),
                            std::mem::take(notifications),
                            now,
                        ));
                    }
                }
            }
        }
    }

    fn tick_monitored_items(
        &mut self,
        now: &DateTimeUtc,
        resend_data: bool,
        max_notifications: usize,
    ) -> Vec<NotificationMessage> {
        let mut notifications = Vec::new();
        let mut messages = Vec::new();
        let mut triggers = Vec::new();

        // If resend data is true, we must visit ever monitored item
        if resend_data {
            for monitored_item in self.monitored_items.values_mut() {
                Self::tick_monitored_item(
                    monitored_item,
                    now,
                    resend_data,
                    max_notifications,
                    &mut triggers,
                    &mut notifications,
                    &mut messages,
                    &mut self.sequence_number,
                );
            }
        } else {
            for item_id in self.notified_monitored_items.drain() {
                let Some(monitored_item) = self.monitored_items.get_mut(&item_id) else {
                    continue;
                };
                Self::tick_monitored_item(
                    monitored_item,
                    now,
                    resend_data,
                    max_notifications,
                    &mut triggers,
                    &mut notifications,
                    &mut messages,
                    &mut self.sequence_number,
                );
            }
        }

        self.handle_triggers(
            now,
            triggers,
            &mut notifications,
            max_notifications,
            &mut messages,
        );

        if notifications.len() > 0 {
            messages.push(Self::make_notification_message(
                self.sequence_number.next(),
                notifications,
                now,
            ));
        }

        messages
    }

    /// Reset the keep-alive counter to the maximum keep-alive count of the Subscription.
    /// The maximum keep-alive count is set by the Client when the Subscription is created
    /// and may be modified using the ModifySubscription Service
    pub fn reset_keep_alive_counter(&mut self) {
        self.keep_alive_counter = self.max_keep_alive_counter;
    }

    /// Reset the lifetime counter to the value specified for the life time of the subscription
    /// in the create subscription service
    pub fn reset_lifetime_counter(&mut self) {
        self.lifetime_counter = self.max_lifetime_counter;
    }

    /// Start or restart the publishing timer and decrement the LifetimeCounter Variable.
    pub fn start_publishing_timer(&mut self) {
        self.lifetime_counter -= 1;
        trace!("Decrementing life time counter {}", self.lifetime_counter);
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn priority(&self) -> u8 {
        self.priority
    }

    pub fn set_publishing_interval(&mut self, publishing_interval: Duration) {
        self.publishing_interval = publishing_interval;
        self.reset_lifetime_counter();
    }

    pub fn set_max_lifetime_counter(&mut self, max_lifetime_counter: u32) {
        self.max_lifetime_counter = max_lifetime_counter;
    }

    pub fn set_max_keep_alive_counter(&mut self, max_keep_alive_counter: u32) {
        self.max_keep_alive_counter = max_keep_alive_counter;
    }

    pub fn set_priority(&mut self, priority: u8) {
        self.priority = priority;
    }

    pub fn set_max_notifications_per_publish(&mut self, max_notifications_per_publish: usize) {
        self.max_notifications_per_publish = max_notifications_per_publish;
    }

    pub fn set_publishing_enabled(&mut self, publishing_enabled: bool) {
        self.publishing_enabled = publishing_enabled;
    }
}
