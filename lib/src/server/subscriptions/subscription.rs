use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

use crate::{
    core::handle::Handle,
    server::Event,
    types::{DataValue, DateTime, DateTimeUtc, NotificationMessage, StatusCode},
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(super) enum TickResult {
    Expired,
    Enqueued,
    None,
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
            // This check is not in the spec, but without it the lifetime counter won't behave properly.
            // This is probably an error in the standard.
            (SubscriptionState::Late, TickReason::TickTimerFired) if self.lifetime_counter > 1 => {
                HandledState::Late12
            }
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
                SubscriptionState::Normal | SubscriptionState::Late | SubscriptionState::KeepAlive,
                TickReason::TickTimerFired,
            ) if self.lifetime_counter <= 1 => HandledState::Closed27,
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
                self.state = SubscriptionState::Late;
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
                UpdateStateAction::ReturnNotifications
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
                self.state = SubscriptionState::Late;
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

    pub(super) fn tick(
        &mut self,
        now: &DateTimeUtc,
        now_instant: Instant,
        tick_reason: TickReason,
        publishing_req_queued: bool,
    ) -> TickResult {
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
            return TickResult::None;
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
            UpdateStateAction::None => TickResult::None,
            UpdateStateAction::ReturnKeepAlive => {
                let notification = NotificationMessage::keep_alive(
                    self.sequence_number.next(),
                    DateTime::from(*now),
                );
                self.enqueue_notification(notification);
                TickResult::Enqueued
            }
            UpdateStateAction::ReturnNotifications => {
                let resend_data = std::mem::take(&mut self.resend_data);
                let messages = self.tick_monitored_items(now, resend_data);
                for msg in messages {
                    self.enqueue_notification(msg);
                }
                TickResult::Enqueued
            }
            UpdateStateAction::SubscriptionCreated => TickResult::None,
            UpdateStateAction::SubscriptionExpired => {
                debug!("Subscription status change to closed / timeout");
                self.monitored_items.clear();
                let notification = NotificationMessage::status_change(
                    self.sequence_number.next(),
                    DateTime::from(*now),
                    StatusCode::BadTimeout,
                );
                self.enqueue_notification(notification);
                TickResult::Expired
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

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use chrono::Utc;

    use crate::{
        server::{
            subscriptions::monitored_item::{tests::new_monitored_item, FilterType, Notification},
            SubscriptionState,
        },
        types::{
            AttributeId, DataChangeNotification, DataValue, DateTime, DateTimeUtc, DecodingOptions,
            EventNotificationList, MonitoringMode, NodeId, NotificationMessage, ObjectId,
            ReadValueId, StatusChangeNotification, StatusCode, Variant,
        },
    };

    use super::{Subscription, TickReason};

    fn get_notifications(message: &NotificationMessage) -> Vec<Notification> {
        let mut res = Vec::new();
        for it in message.notification_data.iter().flatten() {
            match it.node_id.as_object_id().unwrap() {
                ObjectId::DataChangeNotification_Encoding_DefaultBinary => {
                    let notif = it
                        .decode_inner::<DataChangeNotification>(&DecodingOptions::test())
                        .unwrap();
                    for n in notif.monitored_items.into_iter().flatten() {
                        res.push(Notification::MonitoredItemNotification(n));
                    }
                }
                ObjectId::EventNotificationList_Encoding_DefaultBinary => {
                    let notif = it
                        .decode_inner::<EventNotificationList>(&DecodingOptions::test())
                        .unwrap();
                    for n in notif.events.into_iter().flatten() {
                        res.push(Notification::Event(n));
                    }
                }
                _ => panic!("Wrong message type"),
            }
        }
        res
    }

    fn offset(time: DateTimeUtc, time_inst: Instant, ms: u64) -> (DateTimeUtc, Instant) {
        (
            time + chrono::Duration::try_milliseconds(ms as i64).unwrap(),
            time_inst + Duration::from_millis(ms),
        )
    }

    #[test]
    fn tick() {
        let mut sub = Subscription::new(1, true, Duration::from_millis(100), 100, 20, 1, 100, 1000);
        let start = Instant::now();
        let start_dt = Utc::now();

        sub.last_time_publishing_interval_elapsed = start;

        // Subscription is creating, handle the first tick.
        assert_eq!(sub.state, SubscriptionState::Creating);
        sub.tick(&start_dt, start, TickReason::TickTimerFired, true);
        assert_eq!(sub.state, SubscriptionState::Normal);
        assert!(!sub.first_message_sent);

        // Tick again before the publishing interval has elapsed, should change nothing.
        sub.tick(&start_dt, start, TickReason::TickTimerFired, true);
        assert_eq!(sub.state, SubscriptionState::Normal);
        assert!(!sub.first_message_sent);

        // Add a monitored item
        sub.insert(
            1,
            new_monitored_item(
                1,
                ReadValueId {
                    node_id: NodeId::null(),
                    attribute_id: AttributeId::Value as u32,
                    ..Default::default()
                },
                MonitoringMode::Reporting,
                FilterType::None,
                100.0,
                false,
                Some(DataValue::new_now(123)),
            ),
        );
        // New tick at next publishing interval should produce something
        let (time, time_inst) = offset(start_dt, start, 100);
        sub.tick(&time, time_inst, TickReason::TickTimerFired, true);
        assert_eq!(sub.state, SubscriptionState::Normal);
        assert!(sub.first_message_sent);
        let notif = sub.take_notification().unwrap();
        let its = get_notifications(&notif);
        assert_eq!(its.len(), 1);
        let Notification::MonitoredItemNotification(m) = &its[0] else {
            panic!("Wrong notification type");
        };
        assert_eq!(m.value.value, Some(Variant::Int32(123)));

        // Next tick produces nothing
        let (time, time_inst) = offset(start_dt, start, 200);

        sub.tick(&time, time_inst, TickReason::TickTimerFired, true);
        // State transitions to keep alive due to empty publish.
        assert_eq!(sub.state, SubscriptionState::KeepAlive);
        assert_eq!(sub.lifetime_counter, 98);
        assert!(sub.first_message_sent);
        assert!(sub.take_notification().is_none());

        // Enqueue a new notification
        sub.notify_data_value(
            &1,
            DataValue::new_at(
                321,
                DateTime::from(start_dt + chrono::Duration::try_milliseconds(300).unwrap()),
            ),
        );
        let (time, time_inst) = offset(start_dt, start, 300);
        sub.tick(&time, time_inst, TickReason::TickTimerFired, true);
        // State transitions back to normal.
        assert_eq!(sub.state, SubscriptionState::Normal);
        assert!(sub.first_message_sent);
        assert_eq!(sub.lifetime_counter, 99);
        let notif = sub.take_notification().unwrap();
        let its = get_notifications(&notif);
        assert_eq!(its.len(), 1);
        let Notification::MonitoredItemNotification(m) = &its[0] else {
            panic!("Wrong notification type");
        };
        assert_eq!(m.value.value, Some(Variant::Int32(321)));

        for i in 0..20 {
            let (time, time_inst) = offset(start_dt, start, 1000 + i * 100);
            sub.tick(&time, time_inst, TickReason::TickTimerFired, true);
            assert_eq!(sub.state, SubscriptionState::KeepAlive);
            assert_eq!(sub.lifetime_counter, (99 - i - 1) as u32);
            assert_eq!(sub.keep_alive_counter, (20 - i) as u32);
            assert!(sub.take_notification().is_none());
        }
        assert_eq!(sub.lifetime_counter, 79);
        assert_eq!(sub.keep_alive_counter, 1);

        // Tick one more time to get a keep alive
        let (time, time_inst) = offset(start_dt, start, 3000);
        sub.tick(&time, time_inst, TickReason::TickTimerFired, true);
        assert_eq!(sub.state, SubscriptionState::KeepAlive);
        assert_eq!(sub.lifetime_counter, 78);
        assert_eq!(sub.keep_alive_counter, 20);
        let notif = sub.take_notification().unwrap();
        let its = get_notifications(&notif);
        assert!(its.is_empty());

        // Tick another 20 times to become late
        for i in 0..19 {
            let (time, time_inst) = offset(start_dt, start, 3100 + i * 100);
            sub.tick(&time, time_inst, TickReason::TickTimerFired, false);
            assert_eq!(sub.state, SubscriptionState::KeepAlive);
            assert_eq!(sub.lifetime_counter, (78 - i - 1) as u32);
        }

        // Tick another 58 times to expire
        for i in 0..58 {
            let (time, time_inst) = offset(start_dt, start, 5100 + i * 100);
            sub.tick(&time, time_inst, TickReason::TickTimerFired, false);
            assert_eq!(sub.state, SubscriptionState::Late);
            assert_eq!(sub.lifetime_counter, (58 - i) as u32);
        }
        assert_eq!(sub.lifetime_counter, 1);

        let (time, time_inst) = offset(start_dt, start, 20000);
        sub.tick(&time, time_inst, TickReason::TickTimerFired, false);
        assert_eq!(sub.state, SubscriptionState::Closed);
        let notif = sub.take_notification().unwrap();
        assert_eq!(1, notif.notification_data.as_ref().unwrap().len());
        let status_change = notif.notification_data.as_ref().unwrap()[0]
            .decode_inner::<StatusChangeNotification>(&DecodingOptions::test())
            .unwrap();
        assert_eq!(status_change.status, StatusCode::BadTimeout);
    }

    #[test]
    fn monitored_item_triggers() {
        let mut sub = Subscription::new(1, true, Duration::from_millis(100), 100, 20, 1, 100, 1000);
        let start = Instant::now();
        let start_dt = Utc::now();

        sub.last_time_publishing_interval_elapsed = start;
        for i in 0..4 {
            sub.insert(
                i + 1,
                new_monitored_item(
                    i + 1,
                    ReadValueId {
                        node_id: NodeId::null(),
                        attribute_id: AttributeId::Value as u32,
                        ..Default::default()
                    },
                    if i == 0 {
                        MonitoringMode::Reporting
                    } else if i == 3 {
                        MonitoringMode::Disabled
                    } else {
                        MonitoringMode::Sampling
                    },
                    FilterType::None,
                    100.0,
                    false,
                    Some(DataValue::new_at(0, start_dt.into())),
                ),
            );
        }
        sub.get_mut(&1).unwrap().set_triggering(&[1, 2, 3, 4], &[]);
        // Notify the two sampling items and the disabled item
        let (time, time_inst) = offset(start_dt, start, 100);
        sub.notify_data_value(&2, DataValue::new_at(1, time.into()));
        sub.notify_data_value(&3, DataValue::new_at(1, time.into()));
        sub.notify_data_value(&4, DataValue::new_at(1, time.into()));

        // Should not cause a notification
        sub.tick(&time, time_inst, TickReason::TickTimerFired, true);
        assert!(sub.take_notification().is_none());

        // Notify the first item
        sub.notify_data_value(&1, DataValue::new_at(1, time.into()));
        let (time, time_inst) = offset(start_dt, start, 200);
        sub.tick(&time, time_inst, TickReason::TickTimerFired, true);
        let notif = sub.take_notification().unwrap();
        let its = get_notifications(&notif);
        assert_eq!(its.len(), 6);
        for it in its {
            let Notification::MonitoredItemNotification(_m) = it else {
                panic!("Wrong notification type");
            };
        }
    }
}
