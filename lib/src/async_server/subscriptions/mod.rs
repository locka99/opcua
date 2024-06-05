mod monitored_item;
mod subscription;

use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::Utc;
use hashbrown::HashMap;
pub use monitored_item::CreateMonitoredItem;
use subscription::{Subscription, TickReason};

use crate::{
    server::prelude::{
        CreateSubscriptionRequest, CreateSubscriptionResponse, DateTime, DateTimeUtc,
        MessageSecurityMode, NotificationMessage, PublishRequest, PublishResponse, ResponseHeader,
        ServiceFault, StatusCode, SupportedMessage, TransferResult, TransferSubscriptionsRequest,
        TransferSubscriptionsResponse,
    },
    sync::{Mutex, RwLock},
};

use super::{authenticator::UserToken, constants, info::ServerInfo, session::instance::Session};

pub struct SubscriptionCache {
    /// Map from session ID to subscription cache
    session_subscriptions: RwLock<HashMap<u32, Arc<Mutex<SessionSubscriptions>>>>,
    /// Configured limits on subscriptions.
    limits: SubscriptionLimits,
}

impl SubscriptionCache {
    pub fn new(limits: SubscriptionLimits) -> Self {
        Self {
            session_subscriptions: RwLock::new(HashMap::new()),
            limits,
        }
    }

    pub(crate) fn periodic_tick(&self) {
        let now = Utc::now();
        let now_instant = Instant::now();
        let lck = trace_read_lock!(self.session_subscriptions);
        for (_, sub) in lck.iter() {
            let mut sub_lck = sub.lock();
            sub_lck.tick(&now, now_instant, TickReason::TickTimerFired);
        }
    }

    fn get_key(session: &RwLock<Session>) -> PersistentSessionKey {
        let lck = trace_read_lock!(session);
        PersistentSessionKey::new(
            lck.user_token().unwrap(),
            lck.message_security_mode(),
            &lck.application_description().application_uri.as_ref(),
        )
    }

    pub fn get(
        &self,
        session_id: u32,
        session: &RwLock<Session>,
    ) -> Arc<Mutex<SessionSubscriptions>> {
        {
            let lck = trace_read_lock!(self.session_subscriptions);
            if let Some(r) = lck.get(&session_id) {
                return r.clone();
            }
        }

        let mut lck = trace_write_lock!(self.session_subscriptions);
        lck.entry(session_id)
            .or_insert_with(|| {
                Arc::new(Mutex::new(SessionSubscriptions::new(
                    self.limits,
                    Self::get_key(session),
                )))
            })
            .clone()
    }

    pub fn transfer(
        &self,
        req: TransferSubscriptionsRequest,
        session_id: u32,
        session: &RwLock<Session>,
    ) -> TransferSubscriptionsResponse {
        let mut results: Vec<_> = req
            .subscription_ids
            .iter()
            .flatten()
            .map(|id| {
                (
                    *id,
                    TransferResult {
                        status_code: StatusCode::BadSubscriptionIdInvalid,
                        available_sequence_numbers: None,
                    },
                )
            })
            .collect();

        let key = Self::get_key(session);
        {
            let mut lck = trace_write_lock!(self.session_subscriptions);
            let session_subs = lck
                .entry(session_id)
                .or_insert_with(|| {
                    Arc::new(Mutex::new(SessionSubscriptions::new(
                        self.limits,
                        key.clone(),
                    )))
                })
                .clone();
            let mut session_subs_lck = session_subs.lock();

            for (s_id, sub) in lck.iter() {
                if s_id == &session_id {
                    // Without this we would deadlock here, and also we don't want to transfer from the
                    // current session to itself.
                    continue;
                }
                let mut cache = sub.lock();
                if cache.user_token.is_equivalent_for_transfer(&key) {
                    for (sub_id, res) in &mut results {
                        if let Some(sub) = cache.remove(*sub_id) {
                            res.status_code = StatusCode::Good;
                            res.available_sequence_numbers =
                                cache.available_sequence_numbers(*sub_id);

                            if let Err((e, sub)) = session_subs_lck.insert(sub) {
                                res.status_code = e;
                                let _ = cache.insert(sub);
                            } else if req.send_initial_values {
                                if let Some(sub) = session_subs_lck.get_mut(*sub_id) {
                                    sub.set_resend_data();
                                }
                            }
                        }
                    }
                } else {
                    for (sub_id, res) in &mut results {
                        if cache.contains(*sub_id) {
                            res.status_code = StatusCode::BadUserAccessDenied;
                        }
                    }
                }
            }
        }

        TransferSubscriptionsResponse {
            response_header: ResponseHeader::new_good(&req.request_header),
            results: Some(results.into_iter().map(|r| r.1).collect()),
            diagnostic_infos: None,
        }
    }
}

pub(crate) struct PendingPublish {
    pub response: tokio::sync::oneshot::Sender<SupportedMessage>,
    pub request: Box<PublishRequest>,
    pub ack_results: Option<Vec<StatusCode>>,
    pub deadline: Instant,
}

struct NonAckedPublish {
    message: NotificationMessage,
    subscription_id: u32,
}

#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubscriptionLimits {
    pub max_subscriptions_per_session: usize,
    pub max_pending_publish_requests: usize,
    pub max_publish_requests_per_subscription: usize,
    /// Specifies the minimum sampling interval for this server in seconds.
    pub min_sampling_interval_ms: f64,
    /// Specifies the minimum publishing interval for this server in seconds.
    pub min_publishing_interval_ms: f64,
    pub max_keep_alive_count: u32,
    pub default_keep_alive_count: u32,
    /// Maximum number of monitored items per subscription, 0 for no limit
    pub max_monitored_items_per_sub: usize,
    /// Maximum number of values in a monitored item queue
    pub max_monitored_item_queue_size: usize,
    /// Maximum lifetime count (3 times as large as max keep alive)
    pub max_lifetime_count: u32,
}

impl Default for SubscriptionLimits {
    fn default() -> Self {
        Self {
            max_subscriptions_per_session: constants::MAX_SUBSCRIPTIONS_PER_SESSION,
            max_pending_publish_requests: constants::MAX_PENDING_PUBLISH_REQUESTS,
            max_publish_requests_per_subscription: constants::MAX_PUBLISH_REQUESTS_PER_SUBSCRIPTION,
            min_sampling_interval_ms: constants::MIN_SAMPLING_INTERVAL_MS,
            min_publishing_interval_ms: constants::MIN_PUBLISHING_INTERVAL_MS,
            max_monitored_items_per_sub: constants::DEFAULT_MAX_MONITORED_ITEMS_PER_SUB,
            max_monitored_item_queue_size: constants::MAX_DATA_CHANGE_QUEUE_SIZE,
            max_keep_alive_count: constants::MAX_KEEP_ALIVE_COUNT,
            default_keep_alive_count: constants::DEFAULT_KEEP_ALIVE_COUNT,
            max_lifetime_count: constants::MAX_KEEP_ALIVE_COUNT * 3,
        }
    }
}

#[derive(Debug, Clone)]
struct PersistentSessionKey {
    token: UserToken,
    security_mode: MessageSecurityMode,
    application_uri: String,
}

impl PersistentSessionKey {
    pub fn new(
        token: &UserToken,
        security_mode: MessageSecurityMode,
        application_uri: &str,
    ) -> Self {
        Self {
            token: token.clone(),
            security_mode,
            application_uri: application_uri.to_owned(),
        }
    }

    pub fn is_equivalent_for_transfer(&self, other: &PersistentSessionKey) -> bool {
        if self.token.is_anonymous() {
            other.token.is_anonymous()
                && matches!(
                    other.security_mode,
                    MessageSecurityMode::Sign | MessageSecurityMode::SignAndEncrypt
                )
                && self.application_uri == other.application_uri
        } else {
            other.token == self.token
        }
    }
}

/// Subscriptions belonging to a single session. Note that they are technically _owned_ by
/// a user token, which means that they can be transfered to a different session.
pub(crate) struct SessionSubscriptions {
    /// Identity token of the user that created the subscription, used for transfer subscriptions.
    user_token: PersistentSessionKey,
    /// Subscriptions associated with the session.
    subscriptions: HashMap<u32, Subscription>,
    /// Publish request queue (requests by the client on the session)
    publish_request_queue: VecDeque<PendingPublish>,
    /// Notifications that have been sent but have yet to be acknowledged (retransmission queue).
    retransmission_queue: VecDeque<NonAckedPublish>,
    /// Configured limits on subscriptions.
    limits: SubscriptionLimits,
}

impl SessionSubscriptions {
    pub fn new(limits: SubscriptionLimits, user_token: PersistentSessionKey) -> Self {
        Self {
            user_token,
            subscriptions: HashMap::new(),
            publish_request_queue: VecDeque::new(),
            retransmission_queue: VecDeque::new(),
            limits,
        }
    }

    fn max_publish_requests(&self) -> usize {
        self.limits
            .max_pending_publish_requests
            .min(self.subscriptions.len() * self.limits.max_publish_requests_per_subscription)
            .max(1)
    }

    pub fn is_ready_to_delete(&self) -> bool {
        self.subscriptions.is_empty() && self.publish_request_queue.is_empty()
    }

    /// Tests if the subscriptions contain the supplied subscription id.
    pub fn contains(&self, subscription_id: u32) -> bool {
        self.subscriptions.contains_key(&subscription_id)
    }

    pub fn insert(&mut self, subscription: Subscription) -> Result<(), (StatusCode, Subscription)> {
        if self.subscriptions.len() >= self.limits.max_subscriptions_per_session {
            return Err((StatusCode::BadTooManySubscriptions, subscription));
        }
        self.subscriptions.insert(subscription.id(), subscription);
        Ok(())
    }

    pub fn remove(&mut self, subscription_id: u32) -> Option<Subscription> {
        self.subscriptions.remove(&subscription_id)
    }

    pub fn get_mut(&mut self, subscription_id: u32) -> Option<&mut Subscription> {
        self.subscriptions.get_mut(&subscription_id)
    }

    pub fn create_subscription(
        &mut self,
        request: &CreateSubscriptionRequest,
        info: &ServerInfo,
    ) -> Result<CreateSubscriptionResponse, StatusCode> {
        if self.subscriptions.len() >= self.limits.max_subscriptions_per_session {
            return Err(StatusCode::BadTooManySubscriptions);
        }
        let subscription_id = info.subscription_id_handle.next();

        let (revised_publishing_interval, revised_max_keep_alive_count, revised_lifetime_count) =
            Self::revise_subscription_values(
                info,
                request.requested_publishing_interval,
                request.requested_max_keep_alive_count,
                request.requested_lifetime_count,
            );

        let subscription = Subscription::new(
            subscription_id,
            request.publishing_enabled,
            Duration::from_millis(revised_publishing_interval as u64),
            revised_lifetime_count,
            revised_max_keep_alive_count,
            request.priority,
        );
        self.subscriptions.insert(subscription.id(), subscription);
        Ok(CreateSubscriptionResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            subscription_id,
            revised_publishing_interval,
            revised_lifetime_count,
            revised_max_keep_alive_count,
        })
    }

    /// This function takes the requested values passed in a create / modify and returns revised
    /// values that conform to the server's limits. For simplicity the return type is a tuple
    fn revise_subscription_values(
        info: &ServerInfo,
        requested_publishing_interval: f64,
        requested_max_keep_alive_count: u32,
        requested_lifetime_count: u32,
    ) -> (f64, u32, u32) {
        let revised_publishing_interval = f64::max(
            requested_publishing_interval,
            info.config.limits.subscriptions.min_publishing_interval_ms,
        );
        let revised_max_keep_alive_count = if requested_max_keep_alive_count
            > info.config.limits.subscriptions.max_keep_alive_count
        {
            info.config.limits.subscriptions.max_keep_alive_count
        } else if requested_max_keep_alive_count == 0 {
            info.config.limits.subscriptions.default_keep_alive_count
        } else {
            requested_max_keep_alive_count
        };
        // Lifetime count must exceed keep alive count by at least a multiple of
        let min_lifetime_count = revised_max_keep_alive_count * 3;
        let revised_lifetime_count = if requested_lifetime_count < min_lifetime_count {
            min_lifetime_count
        } else if requested_lifetime_count > info.config.limits.subscriptions.max_lifetime_count {
            info.config.limits.subscriptions.max_lifetime_count
        } else {
            requested_lifetime_count
        };
        (
            revised_publishing_interval,
            revised_max_keep_alive_count,
            revised_lifetime_count,
        )
    }

    pub(crate) fn enqueue_publish_request(
        &mut self,
        now: &DateTimeUtc,
        now_instant: Instant,
        mut request: PendingPublish,
    ) {
        if self.publish_request_queue.len() >= self.max_publish_requests() {
            // Tick to trigger publish, maybe remove a request to make space for new one
            let _ = self.tick(now, now_instant, TickReason::ReceivePublishRequest);
        }

        if self.publish_request_queue.len() >= self.max_publish_requests() {
            // Pop the oldest publish request from the queue and return it with an error
            let req = self.publish_request_queue.pop_front().unwrap();
            // Ignore the result of this, if it fails it just means that the
            // channel is disconnected.
            let _ = req.response.send(
                ServiceFault::new(
                    &req.request.request_header,
                    StatusCode::BadTooManyPublishRequests,
                )
                .into(),
            );
        }

        request.ack_results = self.process_subscription_acks(&request.request);
        self.publish_request_queue.push_back(request);
        self.tick(now, now_instant, TickReason::ReceivePublishRequest);
    }

    pub(crate) fn tick(
        &mut self,
        now: &DateTimeUtc,
        now_instant: Instant,
        tick_reason: TickReason,
    ) {
        if self.subscriptions.is_empty() {
            for pb in self.publish_request_queue.drain(..) {
                let _ = pb.response.send(
                    ServiceFault::new(&pb.request.request_header, StatusCode::BadNoSubscription)
                        .into(),
                );
            }
            return;
        }

        self.remove_expired_publish_requests(now_instant);

        let subscription_ids = {
            // Sort subscriptions by priority
            let mut subscription_priority: Vec<(u32, u8)> = self
                .subscriptions
                .values()
                .map(|v| (v.id(), v.priority()))
                .collect();
            subscription_priority.sort_by(|s1, s2| s1.1.cmp(&s2.1));
            subscription_priority.into_iter().map(|s| s.0)
        };

        let mut responses = Vec::new();
        let mut more_notifications = false;

        for sub_id in subscription_ids {
            let subscription = self.subscriptions.get_mut(&sub_id).unwrap();
            subscription.tick(
                now,
                now_instant,
                tick_reason,
                !self.publish_request_queue.is_empty(),
            );
            // Get notifications and publish request pairs while there are any of either left.
            while !self.publish_request_queue.is_empty() {
                if let Some(notification_message) = subscription.take_notification() {
                    let publish_request = self.publish_request_queue.pop_front().unwrap();
                    responses.push((publish_request, notification_message, sub_id));
                } else {
                    break;
                }
            }
            // Make sure to note if there are more notifications in any subscription.
            more_notifications |= subscription.more_notifications();

            if subscription.ready_to_remove() {
                self.subscriptions.remove(&sub_id);
                self.retransmission_queue
                    .retain(|f| f.subscription_id != sub_id);
            }
        }

        let num_responses = responses.len();
        for (idx, (publish_request, notification, subscription_id)) in
            responses.into_iter().enumerate()
        {
            let is_last = idx == num_responses - 1;

            let available_sequence_numbers = self.available_sequence_numbers(subscription_id);

            if self.retransmission_queue.len() >= self.max_publish_requests() * 2 {
                self.retransmission_queue.pop_front();
            }
            self.retransmission_queue.push_back(NonAckedPublish {
                message: notification.clone(),
                subscription_id,
            });

            let _ = publish_request.response.send(
                PublishResponse {
                    response_header: ResponseHeader::new_timestamped_service_result(
                        DateTime::from(*now),
                        &publish_request.request.request_header,
                        StatusCode::Good,
                    ),
                    subscription_id,
                    available_sequence_numbers,
                    // Only set more_notifications on the last publish response.
                    more_notifications: is_last && more_notifications,
                    notification_message: notification,
                    results: publish_request.ack_results,
                    diagnostic_infos: None,
                }
                .into(),
            );
        }
    }

    pub(crate) fn find_notification_message(
        &self,
        subscription_id: u32,
        sequence_number: u32,
    ) -> Result<NotificationMessage, StatusCode> {
        if !self.subscriptions.contains_key(&subscription_id) {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        }
        let Some(notification) = self.retransmission_queue.iter().find(|m| {
            m.subscription_id == subscription_id && m.message.sequence_number == sequence_number
        }) else {
            return Err(StatusCode::BadMessageNotAvailable);
        };
        Ok(notification.message.clone())
    }

    fn remove_expired_publish_requests(&mut self, now: Instant) {
        let mut idx = 0;
        while idx < self.publish_request_queue.len() {
            if self.publish_request_queue[idx].deadline < now {
                let req = self.publish_request_queue.remove(idx).unwrap();
                let _ = req.response.send(
                    ServiceFault::new(&req.request.request_header, StatusCode::BadTimeout).into(),
                );
            } else {
                idx += 1;
            }
        }
    }

    fn process_subscription_acks(&mut self, request: &PublishRequest) -> Option<Vec<StatusCode>> {
        let acks = request.subscription_acknowledgements.as_ref()?;
        if acks.is_empty() {
            return None;
        }

        Some(
            acks.iter()
                .map(|ack| {
                    if !self.subscriptions.contains_key(&ack.subscription_id) {
                        StatusCode::BadSubscriptionIdInvalid
                    } else if let Some((idx, _)) =
                        self.retransmission_queue.iter().enumerate().find(|(_, p)| {
                            p.subscription_id == ack.subscription_id
                                && p.message.sequence_number == ack.sequence_number
                        })
                    {
                        // This is potentially innefficient, but this is probably fine due to two factors:
                        //  - we need unordered removal, _and_ ordered removal, which means we need to deal
                        //    with this anyway.
                        //  - The queue is likely to be short, and the element to be removed is likely to be the
                        //    first.
                        self.retransmission_queue.remove(idx);
                        StatusCode::Good
                    } else {
                        StatusCode::BadSequenceNumberUnknown
                    }
                })
                .collect(),
        )
    }

    /// Returns the array of available sequence numbers in the retransmission queue for the specified subscription
    pub(self) fn available_sequence_numbers(&self, subscription_id: u32) -> Option<Vec<u32>> {
        if self.retransmission_queue.is_empty() {
            return None;
        }
        // Find the notifications matching this subscription id in the retransmission queue
        let sequence_numbers: Vec<u32> = self
            .retransmission_queue
            .iter()
            .filter(|&k| k.subscription_id == subscription_id)
            .map(|k| k.message.sequence_number)
            .collect();
        if sequence_numbers.is_empty() {
            None
        } else {
            Some(sequence_numbers)
        }
    }

    pub(crate) fn user_token(&self) -> &PersistentSessionKey {
        &self.user_token
    }
}
