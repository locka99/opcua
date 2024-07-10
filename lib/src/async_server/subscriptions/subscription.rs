use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

use crate::{
    async_server::Event,
    core::handle::Handle,
    server::prelude::{DataValue, DateTime, DateTimeUtc, NotificationMessage, StatusCode},
};

use super::monitored_item::{MonitoredItem, Notification};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SubscriptionState {
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
        max_notifications_per_publish: u64,
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
            max_notifications_per_publish: max_notifications_per_publish as usize,
        }
    }

    pub fn len(&self) -> usize {
        self.monitored_items.len()
    }

    pub(super) fn get_mut(&mut self, id: &u32) -> Option<&mut MonitoredItem> {
        self.monitored_items.get_mut(id)
    }

    pub fn get(&self, id: &u32) -> Option<&MonitoredItem> {
        self.monitored_items.get(id)
    }

    pub fn contains_key(&self, id: &u32) -> bool {
        self.monitored_items.contains_key(id)
    }

    pub(super) fn drain<'a>(&'a mut self) -> impl Iterator<Item = (u32, MonitoredItem)> + 'a {
        self.monitored_items.drain()
    }

    pub(super) fn set_resend_data(&mut self) {
        self.resend_data = true;
    }

    pub(super) fn remove(&mut self, id: &u32) -> Option<MonitoredItem> {
        self.monitored_items.remove(id)
    }

    pub(super) fn insert(&mut self, id: u32, item: MonitoredItem) {
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

    pub fn notify_event(&mut self, id: &u32, event: &dyn Event) {
        if let Some(item) = self.monitored_items.get_mut(id) {
            if item.notify_event(event) {
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

    fn get_state_transition(
        &self,
        tick_reason: TickReason,
        p: SubscriptionStateParams,
    ) -> HandledState {
        // The full state transition table from Part 4 5.13.1.
        // Note that the exact layout here is written to be as close as possible to the state transition
        // table. Avoid changing it to clean it up or remove redundant checks. To make it easier to debug,
        // it should be as one-to-one with the original document as possible.
        match (self.state, tick_reason) {
            (SubscriptionState::Creating, _) => HandledState::Create3,
            (SubscriptionState::Normal, TickReason::ReceivePublishRequest)
                if self.publishing_enabled || !self.publishing_enabled && !p.more_notifications =>
            {
                HandledState::Normal4
            }
            (SubscriptionState::Normal, TickReason::ReceivePublishRequest)
                if self.publishing_enabled && p.more_notifications =>
            {
                HandledState::Normal5
            }
            (SubscriptionState::Normal, TickReason::TickTimerFired)
                if p.publishing_req_queued
                    && self.publishing_enabled
                    && p.notifications_available =>
            {
                HandledState::IntervalElapsed6
            }
            (SubscriptionState::Normal, TickReason::TickTimerFired)
                if p.publishing_req_queued
                    && !self.first_message_sent
                    && (!self.publishing_enabled
                        || self.publishing_enabled && !p.more_notifications) =>
            {
                HandledState::IntervalElapsed7
            }
            (SubscriptionState::Normal, TickReason::TickTimerFired)
                if !p.publishing_req_queued
                    && (!self.first_message_sent
                        || self.publishing_enabled && p.notifications_available) =>
            {
                HandledState::IntervalElapsed8
            }
            (SubscriptionState::Normal, TickReason::TickTimerFired)
                if self.first_message_sent
                    && (!self.publishing_enabled
                        || self.publishing_enabled && !p.more_notifications) =>
            {
                HandledState::IntervalElapsed9
            }
            (SubscriptionState::Late, TickReason::ReceivePublishRequest)
                if self.publishing_enabled
                    && (p.notifications_available || p.more_notifications) =>
            {
                HandledState::Late10
            }
            (SubscriptionState::Late, TickReason::ReceivePublishRequest)
                if !self.publishing_enabled
                    || self.publishing_enabled
                        && !p.notifications_available
                        && !p.more_notifications =>
            {
                HandledState::Late11
            }
            (SubscriptionState::Late, TickReason::TickTimerFired) => HandledState::Late12,
            (SubscriptionState::KeepAlive, TickReason::ReceivePublishRequest) => {
                HandledState::KeepAlive13
            }
            (SubscriptionState::KeepAlive, TickReason::TickTimerFired)
                if self.publishing_enabled
                    && p.notifications_available
                    && p.publishing_req_queued =>
            {
                HandledState::KeepAlive14
            }
            (SubscriptionState::KeepAlive, TickReason::TickTimerFired)
                if p.publishing_req_queued
                    && self.keep_alive_counter == 1
                    && (!self.publishing_enabled
                        || self.publishing_enabled && !p.notifications_available) =>
            {
                HandledState::KeepAlive15
            }
            (SubscriptionState::KeepAlive, TickReason::TickTimerFired)
                if self.keep_alive_counter > 1
                    && (!self.publishing_enabled
                        || self.publishing_enabled && !p.notifications_available) =>
            {
                HandledState::KeepAlive16
            }
            (SubscriptionState::KeepAlive, TickReason::TickTimerFired)
                if !p.publishing_req_queued
                    && (self.keep_alive_counter == 1
                        || self.keep_alive_counter > 1
                            && self.publishing_enabled
                            && p.notifications_available) =>
            {
                HandledState::KeepAlive17
            }
            // Late is unreachable in the next state.
            (
                SubscriptionState::Normal | SubscriptionState::KeepAlive,
                TickReason::TickTimerFired,
            ) if self.lifetime_counter == 1 => HandledState::Closed27,
            _ => HandledState::None0,
        }
    }

    fn handle_state_transition(&mut self, transition: HandledState) -> UpdateStateAction {
        match transition {
            HandledState::None0 => UpdateStateAction::None,
            HandledState::Create3 => {
                self.state = SubscriptionState::Normal;
                self.first_message_sent = false;
                UpdateStateAction::SubscriptionCreated
            }
            HandledState::Normal4 => {
                // Publish req queued at session level.
                UpdateStateAction::None
            }
            HandledState::Normal5 => {
                self.reset_lifetime_counter();
                UpdateStateAction::ReturnNotifications
            }
            HandledState::IntervalElapsed6 => {
                self.reset_lifetime_counter();
                self.start_publishing_timer();
                self.first_message_sent = true;
                UpdateStateAction::ReturnNotifications
            }
            HandledState::IntervalElapsed7 => {
                self.reset_lifetime_counter();
                self.start_publishing_timer();
                self.first_message_sent = true;
                UpdateStateAction::ReturnKeepAlive
            }
            HandledState::IntervalElapsed8 => {
                self.start_publishing_timer();
                self.state = SubscriptionState::Late;
                UpdateStateAction::None
            }
            HandledState::IntervalElapsed9 => {
                self.start_publishing_timer();
                self.reset_keep_alive_counter();
                self.state = SubscriptionState::KeepAlive;
                UpdateStateAction::None
            }
            HandledState::Late10 => {
                self.reset_lifetime_counter();
                self.first_message_sent = true;
                self.state = SubscriptionState::Normal;
                UpdateStateAction::ReturnNotifications
            }
            HandledState::Late11 => {
                self.reset_lifetime_counter();
                self.first_message_sent = true;
                self.state = SubscriptionState::KeepAlive;
                UpdateStateAction::ReturnKeepAlive
            }
            HandledState::Late12 => {
                self.start_publishing_timer();
                UpdateStateAction::None
            }
            HandledState::KeepAlive13 => {
                // No-op, publish req enqueued at session level.
                UpdateStateAction::None
            }
            HandledState::KeepAlive14 => {
                self.reset_lifetime_counter();
                self.start_publishing_timer();
                self.first_message_sent = true;
                self.state = SubscriptionState::Normal;
                UpdateStateAction::ReturnKeepAlive
            }
            HandledState::KeepAlive15 => {
                self.start_publishing_timer();
                self.reset_keep_alive_counter();
                UpdateStateAction::ReturnKeepAlive
            }
            HandledState::KeepAlive16 => {
                self.start_publishing_timer();
                self.keep_alive_counter -= 1;
                UpdateStateAction::None
            }
            HandledState::KeepAlive17 => {
                self.start_publishing_timer();
                UpdateStateAction::None
            }
            HandledState::Closed27 => {
                self.state = SubscriptionState::Closed;
                UpdateStateAction::SubscriptionExpired
            }
        }
    }

    fn notifications_available(&self, resend_data: bool) -> bool {
        if !self.notified_monitored_items.is_empty() {
            true
        } else if resend_data {
            self.monitored_items.iter().any(|it| it.1.has_last_value())
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

        // We're not actually doing anything in this case.
        if matches!(tick_reason, TickReason::TickTimerFired) && !publishing_interval_elapsed {
            return;
        }
        // First, get the actual state transition we're in.
        let transition = self.get_state_transition(
            tick_reason,
            SubscriptionStateParams {
                notifications_available: self.notifications_available(self.resend_data),
                more_notifications: self.notifications.len() > 0,
                publishing_req_queued,
            },
        );
        let action = self.handle_state_transition(transition);

        match action {
            UpdateStateAction::None => {}
            UpdateStateAction::ReturnKeepAlive => {
                let notification = NotificationMessage::keep_alive(
                    self.sequence_number.next(),
                    DateTime::from(*now),
                );
                self.enqueue_notification(notification);
            }
            UpdateStateAction::ReturnNotifications => {
                let resend_data = std::mem::take(&mut self.resend_data);
                let messages = self.tick_monitored_items(now, resend_data);
                for msg in messages {
                    self.enqueue_notification(msg);
                }
            }
            UpdateStateAction::SubscriptionCreated => {}
            UpdateStateAction::SubscriptionExpired => {
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

    fn handle_triggers(
        &mut self,
        now: &DateTimeUtc,
        triggers: Vec<(u32, u32)>,
        notifications: &mut Vec<Notification>,
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
                if notifications.len() >= self.max_notifications_per_publish
                    && self.max_notifications_per_publish > 0
                {
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
                    self.max_notifications_per_publish,
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
                    self.max_notifications_per_publish,
                    &mut triggers,
                    &mut notifications,
                    &mut messages,
                    &mut self.sequence_number,
                );
            }
        }

        self.handle_triggers(now, triggers, &mut notifications, &mut messages);

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
    pub(super) fn reset_keep_alive_counter(&mut self) {
        self.keep_alive_counter = self.max_keep_alive_counter;
    }

    /// Reset the lifetime counter to the value specified for the life time of the subscription
    /// in the create subscription service
    pub(super) fn reset_lifetime_counter(&mut self) {
        self.lifetime_counter = self.max_lifetime_counter;
    }

    /// Start or restart the publishing timer and decrement the LifetimeCounter Variable.
    pub(super) fn start_publishing_timer(&mut self) {
        self.lifetime_counter -= 1;
        trace!("Decrementing life time counter {}", self.lifetime_counter);
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn priority(&self) -> u8 {
        self.priority
    }

    pub(super) fn set_publishing_interval(&mut self, publishing_interval: Duration) {
        self.publishing_interval = publishing_interval;
        self.reset_lifetime_counter();
    }

    pub(super) fn set_max_lifetime_counter(&mut self, max_lifetime_counter: u32) {
        self.max_lifetime_counter = max_lifetime_counter;
    }

    pub(super) fn set_max_keep_alive_counter(&mut self, max_keep_alive_counter: u32) {
        self.max_keep_alive_counter = max_keep_alive_counter;
    }

    pub(super) fn set_priority(&mut self, priority: u8) {
        self.priority = priority;
    }

    pub(super) fn set_max_notifications_per_publish(&mut self, max_notifications_per_publish: u64) {
        self.max_notifications_per_publish = max_notifications_per_publish as usize;
    }

    pub(super) fn set_publishing_enabled(&mut self, publishing_enabled: bool) {
        self.publishing_enabled = publishing_enabled;
    }

    pub fn publishing_interval(&self) -> Duration {
        self.publishing_interval
    }

    pub fn publishing_enabled(&self) -> bool {
        self.publishing_enabled
    }

    pub fn max_queued_notifications(&self) -> usize {
        self.max_queued_notifications
    }

    pub fn max_notifications_per_publish(&self) -> usize {
        self.max_notifications_per_publish
    }

    pub fn state(&self) -> SubscriptionState {
        self.state
    }
}
