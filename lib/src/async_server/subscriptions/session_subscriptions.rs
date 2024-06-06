use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use super::{
    subscription::{MonitoredItemHandle, Subscription, TickReason},
    NonAckedPublish, PendingPublish, PersistentSessionKey, SubscriptionLimits,
};
use hashbrown::HashMap;

use crate::{
    async_server::info::ServerInfo,
    server::prelude::{
        CreateSubscriptionRequest, CreateSubscriptionResponse, DataValue, DateTime, DateTimeUtc,
        ModifySubscriptionRequest, ModifySubscriptionResponse, NotificationMessage, PublishRequest,
        PublishResponse, RepublishRequest, RepublishResponse, ResponseHeader, ServiceFault,
        SetPublishingModeRequest, SetPublishingModeResponse, StatusCode,
    },
};

/// Subscriptions belonging to a single session. Note that they are technically _owned_ by
/// a user token, which means that they can be transfered to a different session.
pub(super) struct SessionSubscriptions {
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
    pub(super) fn new(limits: SubscriptionLimits, user_token: PersistentSessionKey) -> Self {
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

    pub fn insert(
        &mut self,
        subscription: Subscription,
        notifs: Vec<NonAckedPublish>,
    ) -> Result<(), (StatusCode, Subscription, Vec<NonAckedPublish>)> {
        if self.subscriptions.len() >= self.limits.max_subscriptions_per_session {
            return Err((StatusCode::BadTooManySubscriptions, subscription, notifs));
        }
        self.subscriptions.insert(subscription.id(), subscription);
        for notif in notifs {
            self.retransmission_queue.push_back(notif);
        }
        Ok(())
    }

    pub fn remove(&mut self, subscription_id: u32) -> (Option<Subscription>, Vec<NonAckedPublish>) {
        let mut notifs = Vec::new();
        let mut idx = 0;
        while idx < self.retransmission_queue.len() {
            if self.retransmission_queue[idx].subscription_id == subscription_id {
                notifs.push(self.retransmission_queue.remove(idx).unwrap());
            } else {
                idx += 1;
            }
        }

        (self.subscriptions.remove(&subscription_id), notifs)
    }

    pub fn get_mut(&mut self, subscription_id: u32) -> Option<&mut Subscription> {
        self.subscriptions.get_mut(&subscription_id)
    }

    pub(super) fn create_subscription(
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
            self.limits.max_queued_notifications,
            self.revise_max_notifications_per_publish(request.max_notifications_per_publish),
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

    pub(super) fn modify_subscription(
        &mut self,
        request: &ModifySubscriptionRequest,
        info: &ServerInfo,
    ) -> Result<ModifySubscriptionResponse, StatusCode> {
        let max_notifications_per_publish =
            self.revise_max_notifications_per_publish(request.max_notifications_per_publish);
        let Some(subscription) = self.subscriptions.get_mut(&request.subscription_id) else {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        };

        let (revised_publishing_interval, revised_max_keep_alive_count, revised_lifetime_count) =
            Self::revise_subscription_values(
                info,
                request.requested_publishing_interval,
                request.requested_max_keep_alive_count,
                request.requested_lifetime_count,
            );

        subscription.set_publishing_interval(Duration::from_micros(
            (revised_publishing_interval * 1000.0) as u64,
        ));
        subscription.set_max_keep_alive_counter(revised_max_keep_alive_count);
        subscription.set_max_lifetime_counter(revised_lifetime_count);
        subscription.set_priority(request.priority);
        subscription.reset_lifetime_counter();
        subscription.reset_keep_alive_counter();
        subscription.set_max_notifications_per_publish(max_notifications_per_publish);

        Ok(ModifySubscriptionResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            revised_publishing_interval,
            revised_lifetime_count,
            revised_max_keep_alive_count,
        })
    }

    pub(super) fn set_publishing_mode(
        &mut self,
        request: &SetPublishingModeRequest,
    ) -> Result<SetPublishingModeResponse, StatusCode> {
        let Some(ids) = &request.subscription_ids else {
            return Err(StatusCode::BadNothingToDo);
        };
        if ids.is_empty() {
            return Err(StatusCode::BadNothingToDo);
        }

        let mut results = Vec::new();
        for id in ids {
            results.push(match self.subscriptions.get_mut(id) {
                Some(sub) => {
                    sub.set_publishing_enabled(request.publishing_enabled);
                    sub.reset_lifetime_counter();
                    StatusCode::Good
                }
                None => StatusCode::BadSubscriptionIdInvalid,
            })
        }
        Ok(SetPublishingModeResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            results: Some(results),
            diagnostic_infos: None,
        })
    }

    pub(super) fn republish(
        &self,
        request: &RepublishRequest,
    ) -> Result<RepublishResponse, StatusCode> {
        let msg = self.find_notification_message(
            request.subscription_id,
            request.retransmit_sequence_number,
        )?;
        Ok(RepublishResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            notification_message: msg,
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

    fn revise_max_notifications_per_publish(&self, inp: u32) -> usize {
        if self.limits.max_notifications_per_publish == 0 {
            inp as usize
        } else if inp as usize > self.limits.max_notifications_per_publish {
            self.limits.max_notifications_per_publish
        } else if inp == 0 {
            self.limits.max_notifications_per_publish
        } else {
            inp as usize
        }
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
                self.limits.max_notifications_per_publish,
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

    fn find_notification_message(
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
    pub(super) fn available_sequence_numbers(&self, subscription_id: u32) -> Option<Vec<u32>> {
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

    pub(super) fn notify_data_changes(&mut self, values: Vec<(MonitoredItemHandle, DataValue)>) {
        for (handle, value) in values {
            let Some(sub) = self.subscriptions.get_mut(&handle.subscription_id) else {
                continue;
            };
            let Some(item) = sub.monitored_items.get_mut(&handle.monitored_item_id) else {
                continue;
            };
            item.notify_data_value(value);
        }
    }

    pub(super) fn user_token(&self) -> &PersistentSessionKey {
        &self.user_token
    }
}
