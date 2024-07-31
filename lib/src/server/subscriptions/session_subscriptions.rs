use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

use super::{
    monitored_item::MonitoredItem,
    subscription::{MonitoredItemHandle, Subscription, TickReason, TickResult},
    CreateMonitoredItem, NonAckedPublish, PendingPublish, PersistentSessionKey,
};
use hashbrown::{HashMap, HashSet};

use crate::{
    server::{
        info::ServerInfo,
        node_manager::{MonitoredItemRef, MonitoredItemUpdateRef, TypeTree},
        session::instance::Session,
        Event, SubscriptionLimits,
    },
    sync::RwLock,
    types::{
        AttributeId, CreateSubscriptionRequest, CreateSubscriptionResponse, DataValue, DateTime,
        DateTimeUtc, ExtensionObject, ModifySubscriptionRequest, ModifySubscriptionResponse,
        MonitoredItemCreateResult, MonitoredItemModifyRequest, MonitoredItemModifyResult,
        MonitoringMode, NodeId, NotificationMessage, ObjectId, PublishRequest, PublishResponse,
        RepublishRequest, RepublishResponse, ResponseHeader, ServiceFault,
        SetPublishingModeRequest, SetPublishingModeResponse, StatusCode, TimestampsToReturn,
    },
};

/// Subscriptions belonging to a single session. Note that they are technically _owned_ by
/// a user token, which means that they can be transfered to a different session.
pub struct SessionSubscriptions {
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

    /// Static reference to the session owning this, required to cleanly handle deletion.
    session: Arc<RwLock<Session>>,
}

impl SessionSubscriptions {
    pub(super) fn new(
        limits: SubscriptionLimits,
        user_token: PersistentSessionKey,
        session: Arc<RwLock<Session>>,
    ) -> Self {
        Self {
            user_token,
            subscriptions: HashMap::new(),
            publish_request_queue: VecDeque::new(),
            retransmission_queue: VecDeque::new(),
            limits,
            session,
        }
    }

    fn max_publish_requests(&self) -> usize {
        self.limits
            .max_pending_publish_requests
            .min(self.subscriptions.len() * self.limits.max_publish_requests_per_subscription)
            .max(1)
    }

    pub(super) fn is_ready_to_delete(&self) -> bool {
        self.subscriptions.is_empty() && self.publish_request_queue.is_empty()
    }

    pub(super) fn insert(
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

    /// Return `true` if the session has a subscription with ID given by
    /// `sub_id`.
    pub fn contains(&self, sub_id: u32) -> bool {
        self.subscriptions.contains_key(&sub_id)
    }

    /// Return a vector of all the subscription IDs in this session.
    pub fn subscription_ids(&self) -> Vec<u32> {
        self.subscriptions.keys().copied().collect()
    }

    pub(super) fn remove(
        &mut self,
        subscription_id: u32,
    ) -> (Option<Subscription>, Vec<NonAckedPublish>) {
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

    /// Get a mutable reference to a subscription by ID.
    pub fn get_mut(&mut self, subscription_id: u32) -> Option<&mut Subscription> {
        self.subscriptions.get_mut(&subscription_id)
    }

    /// Get a reference to a subscription by ID.
    pub fn get(&self, subscription_id: u32) -> Option<&Subscription> {
        self.subscriptions.get(&subscription_id)
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

    pub(super) fn create_monitored_items(
        &mut self,
        subscription_id: u32,
        requests: &[CreateMonitoredItem],
    ) -> Result<Vec<MonitoredItemCreateResult>, StatusCode> {
        let Some(sub) = self.subscriptions.get_mut(&subscription_id) else {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        };

        let mut results = Vec::with_capacity(requests.len());
        for item in requests {
            let filter_result = item
                .filter_res()
                .map(|r| {
                    ExtensionObject::from_encodable(
                        ObjectId::EventFilterResult_Encoding_DefaultBinary,
                        r,
                    )
                })
                .unwrap_or_else(|| ExtensionObject::null());
            if item.status_code().is_good() {
                let new_item = MonitoredItem::new(&item);
                results.push(MonitoredItemCreateResult {
                    status_code: StatusCode::Good,
                    monitored_item_id: new_item.id(),
                    revised_sampling_interval: new_item.sampling_interval(),
                    revised_queue_size: new_item.queue_size() as u32,
                    filter_result,
                });
                sub.insert(new_item.id(), new_item);
            } else {
                results.push(MonitoredItemCreateResult {
                    status_code: item.status_code(),
                    monitored_item_id: 0,
                    revised_sampling_interval: item.sampling_interval(),
                    revised_queue_size: item.queue_size() as u32,
                    filter_result,
                });
            }
        }

        Ok(results)
    }

    pub(super) fn modify_monitored_items(
        &mut self,
        subscription_id: u32,
        info: &ServerInfo,
        timestamps_to_return: TimestampsToReturn,
        requests: Vec<MonitoredItemModifyRequest>,
        type_tree: &TypeTree,
    ) -> Result<Vec<MonitoredItemUpdateRef>, StatusCode> {
        let Some(sub) = self.subscriptions.get_mut(&subscription_id) else {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        };
        let mut results = Vec::with_capacity(requests.len());
        for request in requests {
            if let Some(item) = sub.get_mut(&request.monitored_item_id) {
                let (filter_result, status) =
                    item.modify(info, timestamps_to_return, &request, type_tree);
                let filter_result = filter_result
                    .map(|f| {
                        ExtensionObject::from_encodable(
                            ObjectId::EventFilterResult_Encoding_DefaultBinary,
                            &f,
                        )
                    })
                    .unwrap_or_else(|| ExtensionObject::null());

                results.push(MonitoredItemUpdateRef::new(
                    MonitoredItemHandle {
                        subscription_id,
                        monitored_item_id: item.id(),
                    },
                    item.item_to_monitor().node_id.clone(),
                    item.item_to_monitor().attribute_id,
                    MonitoredItemModifyResult {
                        status_code: status,
                        revised_sampling_interval: item.sampling_interval(),
                        revised_queue_size: item.queue_size() as u32,
                        filter_result,
                    },
                ));
            } else {
                results.push(MonitoredItemUpdateRef::new(
                    MonitoredItemHandle {
                        subscription_id,
                        monitored_item_id: request.monitored_item_id,
                    },
                    NodeId::null(),
                    AttributeId::NodeId,
                    MonitoredItemModifyResult {
                        status_code: StatusCode::BadMonitoredItemIdInvalid,
                        revised_sampling_interval: 0.0,
                        revised_queue_size: 0,
                        filter_result: ExtensionObject::null(),
                    },
                ));
            }
        }

        Ok(results)
    }

    pub(super) fn set_monitoring_mode(
        &mut self,
        subscription_id: u32,
        monitoring_mode: MonitoringMode,
        items: Vec<u32>,
    ) -> Result<Vec<(StatusCode, MonitoredItemRef)>, StatusCode> {
        let Some(sub) = self.subscriptions.get_mut(&subscription_id) else {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        };
        let mut results = Vec::with_capacity(items.len());
        for id in items {
            let handle = MonitoredItemHandle {
                subscription_id,
                monitored_item_id: id,
            };
            if let Some(item) = sub.get_mut(&id) {
                results.push((
                    StatusCode::Good,
                    MonitoredItemRef::new(
                        handle,
                        item.item_to_monitor().node_id.clone(),
                        item.item_to_monitor().attribute_id,
                    ),
                ));
                item.set_monitoring_mode(monitoring_mode);
            } else {
                results.push((
                    StatusCode::BadMonitoredItemIdInvalid,
                    MonitoredItemRef::new(handle, NodeId::null(), AttributeId::NodeId),
                ));
            }
        }
        Ok(results)
    }

    fn filter_links(links: Vec<u32>, sub: &Subscription) -> (Vec<u32>, Vec<StatusCode>) {
        let mut to_apply = Vec::with_capacity(links.len());
        let mut results = Vec::with_capacity(links.len());

        for link in links {
            if sub.contains_key(&link) {
                to_apply.push(link);
                results.push(StatusCode::Good);
            } else {
                results.push(StatusCode::BadMonitoredItemIdInvalid);
            }
        }
        (to_apply, results)
    }

    pub(super) fn set_triggering(
        &mut self,
        subscription_id: u32,
        triggering_item_id: u32,
        links_to_add: Vec<u32>,
        links_to_remove: Vec<u32>,
    ) -> Result<(Vec<StatusCode>, Vec<StatusCode>), StatusCode> {
        let Some(sub) = self.subscriptions.get_mut(&subscription_id) else {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        };
        if !sub.contains_key(&triggering_item_id) {
            return Err(StatusCode::BadMonitoredItemIdInvalid);
        }

        let (to_add, add_results) = Self::filter_links(links_to_add, &sub);
        let (to_remove, remove_results) = Self::filter_links(links_to_remove, &sub);

        let item = sub.get_mut(&triggering_item_id).unwrap();

        item.set_triggering(&to_add, &to_remove);

        Ok((add_results, remove_results))
    }

    pub(super) fn delete_monitored_items(
        &mut self,
        subscription_id: u32,
        items: &[u32],
    ) -> Result<Vec<(StatusCode, MonitoredItemRef)>, StatusCode> {
        let Some(sub) = self.subscriptions.get_mut(&subscription_id) else {
            return Err(StatusCode::BadSubscriptionIdInvalid);
        };
        let mut results = Vec::with_capacity(items.len());
        for id in items {
            let handle = MonitoredItemHandle {
                subscription_id,
                monitored_item_id: *id,
            };
            if let Some(item) = sub.remove(&id) {
                results.push((
                    StatusCode::Good,
                    MonitoredItemRef::new(
                        handle,
                        item.item_to_monitor().node_id.clone(),
                        item.item_to_monitor().attribute_id,
                    ),
                ));
            } else {
                results.push((
                    StatusCode::BadMonitoredItemIdInvalid,
                    MonitoredItemRef::new(handle, NodeId::null(), AttributeId::NodeId),
                ))
            }
        }
        Ok(results)
    }

    pub(super) fn delete_subscriptions(
        &mut self,
        ids: &[u32],
    ) -> Vec<(StatusCode, Vec<MonitoredItemRef>)> {
        let id_set: HashSet<_> = ids.iter().copied().collect();
        let mut result = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(mut sub) = self.subscriptions.remove(id) else {
                result.push((StatusCode::BadSubscriptionIdInvalid, Vec::new()));
                continue;
            };

            let items = sub
                .drain()
                .map(|item| {
                    MonitoredItemRef::new(
                        MonitoredItemHandle {
                            subscription_id: *id,
                            monitored_item_id: item.1.id(),
                        },
                        item.1.item_to_monitor().node_id.clone(),
                        item.1.item_to_monitor().attribute_id,
                    )
                })
                .collect();

            result.push((StatusCode::Good, items))
        }

        self.retransmission_queue
            .retain(|r| !id_set.contains(&r.subscription_id));

        result
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

    fn revise_max_notifications_per_publish(&self, inp: u32) -> u64 {
        if self.limits.max_notifications_per_publish == 0 {
            inp as u64
        } else if inp as u64 > self.limits.max_notifications_per_publish {
            self.limits.max_notifications_per_publish
        } else if inp == 0 {
            self.limits.max_notifications_per_publish
        } else {
            inp as u64
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
    ) -> Vec<MonitoredItemRef> {
        let mut to_delete = Vec::new();
        if self.subscriptions.is_empty() {
            for pb in self.publish_request_queue.drain(..) {
                let _ = pb.response.send(
                    ServiceFault::new(&pb.request.request_header, StatusCode::BadNoSubscription)
                        .into(),
                );
            }
            return to_delete;
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
            let res = subscription.tick(
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

            // If the subscription expired, make sure to collect any deleted monitored items.

            if matches!(res, TickResult::Expired) {
                to_delete.extend(subscription.drain().map(|item| {
                    MonitoredItemRef::new(
                        MonitoredItemHandle {
                            subscription_id: sub_id,
                            monitored_item_id: item.1.id(),
                        },
                        item.1.item_to_monitor().node_id.clone(),
                        item.1.item_to_monitor().attribute_id,
                    )
                }))
            }

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

        to_delete
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
            sub.notify_data_value(&handle.monitored_item_id, value);
        }
    }

    pub(super) fn notify_events(&mut self, events: Vec<(MonitoredItemHandle, &dyn Event)>) {
        for (handle, event) in events {
            let Some(sub) = self.subscriptions.get_mut(&handle.subscription_id) else {
                continue;
            };
            sub.notify_event(&handle.monitored_item_id, event);
        }
    }

    pub(super) fn user_token(&self) -> &PersistentSessionKey {
        &self.user_token
    }

    pub(super) fn get_monitored_item_count(&self, subscription_id: u32) -> Option<usize> {
        self.subscriptions.get(&subscription_id).map(|s| s.len())
    }

    /// Get a reference to the session this subscription collection is owned by.
    pub fn session(&self) -> &Arc<RwLock<Session>> {
        &self.session
    }
}
