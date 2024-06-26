mod monitored_item;
mod session_subscriptions;
mod subscription;

use std::{sync::Arc, time::Instant};

use chrono::Utc;
use hashbrown::{Equivalent, HashMap};
pub use monitored_item::CreateMonitoredItem;
use session_subscriptions::SessionSubscriptions;
pub use subscription::MonitoredItemHandle;
use subscription::TickReason;

use crate::{
    server::prelude::{
        AttributeId, CreateSubscriptionRequest, CreateSubscriptionResponse, DataValue, DateTimeUtc,
        MessageSecurityMode, ModifySubscriptionRequest, ModifySubscriptionResponse,
        MonitoredItemCreateResult, MonitoredItemModifyRequest, MonitoredItemModifyResult,
        MonitoringMode, NodeId, NotificationMessage, NumericRange, ObjectId, PublishRequest,
        QualifiedName, RepublishRequest, RepublishResponse, ResponseHeader,
        SetPublishingModeRequest, SetPublishingModeResponse, StatusCode, SupportedMessage,
        TimestampsToReturn, TransferResult, TransferSubscriptionsRequest,
        TransferSubscriptionsResponse,
    },
    sync::{Mutex, RwLock},
};

use super::{
    authenticator::UserToken, info::ServerInfo, node_manager::TypeTree, session::instance::Session,
    Event, SubscriptionLimits,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MonitoredItemKey {
    id: NodeId,
    attribute_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MonitoredItemKeyRef<'a> {
    id: &'a NodeId,
    attribute_id: u32,
}

impl<'a> Equivalent<MonitoredItemKey> for MonitoredItemKeyRef<'a> {
    fn equivalent(&self, key: &MonitoredItemKey) -> bool {
        self.id == &key.id && self.attribute_id == key.attribute_id
    }
}

struct MonitoredItemEntry {
    enabled: bool,
    data_encoding: QualifiedName,
    index_range: NumericRange,
}

struct SubscriptionCacheInner {
    /// Map from session ID to subscription cache
    session_subscriptions: HashMap<u32, Arc<Mutex<SessionSubscriptions>>>,
    /// Map from subscription ID to session ID.
    subscription_to_session: HashMap<u32, u32>,
    /// Map from notifier node ID to monitored item handles.
    monitored_items: HashMap<MonitoredItemKey, HashMap<MonitoredItemHandle, MonitoredItemEntry>>,
}

pub struct SubscriptionCache {
    inner: RwLock<SubscriptionCacheInner>,
    /// Configured limits on subscriptions.
    limits: SubscriptionLimits,
}

impl SubscriptionCache {
    pub fn new(limits: SubscriptionLimits) -> Self {
        Self {
            inner: RwLock::new(SubscriptionCacheInner {
                session_subscriptions: HashMap::new(),
                subscription_to_session: HashMap::new(),
                monitored_items: HashMap::new(),
            }),
            limits,
        }
    }

    pub(crate) fn periodic_tick(&self) {
        let mut to_delete = Vec::new();
        {
            let now = Utc::now();
            let now_instant = Instant::now();
            let lck = trace_read_lock!(self.inner);
            for (session_id, sub) in lck.session_subscriptions.iter() {
                let mut sub_lck = sub.lock();
                sub_lck.tick(&now, now_instant, TickReason::TickTimerFired);
                if sub_lck.is_ready_to_delete() {
                    to_delete.push(*session_id);
                }
            }
        }
        if !to_delete.is_empty() {
            let mut lck = trace_write_lock!(self.inner);
            for id in to_delete {
                lck.session_subscriptions.remove(&id);
            }
        }
    }

    pub(crate) fn get_monitored_item_count(
        &self,
        session_id: u32,
        subscription_id: u32,
    ) -> Option<usize> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        }) else {
            return None;
        };
        let cache_lck = cache.lock();
        cache_lck.get_monitored_item_count(subscription_id)
    }

    pub(crate) fn create_subscription(
        &self,
        session_id: u32,
        session: &RwLock<Session>,
        request: &CreateSubscriptionRequest,
        info: &ServerInfo,
    ) -> Result<CreateSubscriptionResponse, StatusCode> {
        let mut lck = trace_write_lock!(self.inner);
        let cache = lck
            .session_subscriptions
            .entry(session_id)
            .or_insert_with(|| {
                Arc::new(Mutex::new(SessionSubscriptions::new(
                    self.limits,
                    Self::get_key(session),
                )))
            })
            .clone();
        let mut cache_lck = cache.lock();
        let res = cache_lck.create_subscription(request, info)?;
        lck.subscription_to_session
            .insert(res.subscription_id, session_id);
        Ok(res)
    }

    pub(crate) fn modify_subscription(
        &self,
        session_id: u32,
        request: &ModifySubscriptionRequest,
        info: &ServerInfo,
    ) -> Result<ModifySubscriptionResponse, StatusCode> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        }) else {
            return Err(StatusCode::BadNoSubscription);
        };
        let mut cache_lck = cache.lock();
        cache_lck.modify_subscription(request, info)
    }

    pub(crate) fn set_publishing_mode(
        &self,
        session_id: u32,
        request: &SetPublishingModeRequest,
    ) -> Result<SetPublishingModeResponse, StatusCode> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        }) else {
            return Err(StatusCode::BadNoSubscription);
        };
        let mut cache_lck = cache.lock();
        cache_lck.set_publishing_mode(request)
    }

    pub(crate) fn republish(
        &self,
        session_id: u32,
        request: &RepublishRequest,
    ) -> Result<RepublishResponse, StatusCode> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        }) else {
            return Err(StatusCode::BadNoSubscription);
        };
        let cache_lck = cache.lock();
        cache_lck.republish(request)
    }

    pub(crate) fn enqueue_publish_request(
        &self,
        session_id: u32,
        now: &DateTimeUtc,
        now_instant: Instant,
        request: PendingPublish,
    ) -> Result<(), StatusCode> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        }) else {
            return Err(StatusCode::BadNoSubscription);
        };

        let mut cache_lck = cache.lock();
        cache_lck.enqueue_publish_request(now, now_instant, request);
        Ok(())
    }

    pub fn notify_data_change<'a>(
        &self,
        items: impl Iterator<Item = (DataValue, &'a NodeId, AttributeId)>,
    ) {
        let lck = trace_read_lock!(self.inner);
        let mut by_subscription: HashMap<u32, Vec<_>> = HashMap::new();
        for (dv, node_id, attribute_id) in items {
            let key = MonitoredItemKeyRef {
                id: node_id,
                attribute_id: attribute_id as u32,
            };
            let Some(items) = lck.monitored_items.get(&key) else {
                continue;
            };

            for (handle, entry) in items {
                if !entry.enabled {
                    continue;
                }
                by_subscription
                    .entry(handle.subscription_id)
                    .or_default()
                    .push((*handle, dv.clone()));
            }
        }

        for (sub_id, items) in by_subscription {
            let Some(session_id) = lck.subscription_to_session.get(&sub_id) else {
                continue;
            };
            let Some(cache) = lck.session_subscriptions.get(session_id) else {
                continue;
            };
            let mut cache_lck = cache.lock();
            cache_lck.notify_data_changes(items);
        }
    }

    /// Notify with a dynamic sampler, to avoid getting values for nodes that
    /// may not have monitored items.
    pub fn maybe_notify<'a>(
        &self,
        items: impl Iterator<Item = (&'a NodeId, AttributeId)>,
        sample: impl Fn(&NodeId, AttributeId, &NumericRange, &QualifiedName) -> Option<DataValue>,
    ) {
        let lck = trace_read_lock!(self.inner);
        let mut by_subscription: HashMap<u32, Vec<_>> = HashMap::new();
        for (node_id, attribute_id) in items {
            let key = MonitoredItemKeyRef {
                id: node_id,
                attribute_id: attribute_id as u32,
            };
            let Some(items) = lck.monitored_items.get(&key) else {
                continue;
            };

            for (handle, entry) in items {
                if !entry.enabled {
                    continue;
                }
                let Some(dv) = sample(
                    node_id,
                    attribute_id,
                    &entry.index_range,
                    &entry.data_encoding,
                ) else {
                    continue;
                };
                by_subscription
                    .entry(handle.subscription_id)
                    .or_default()
                    .push((*handle, dv));
            }
        }

        for (sub_id, items) in by_subscription {
            let Some(session_id) = lck.subscription_to_session.get(&sub_id) else {
                continue;
            };
            let Some(cache) = lck.session_subscriptions.get(session_id) else {
                continue;
            };
            let mut cache_lck = cache.lock();
            cache_lck.notify_data_changes(items);
        }
    }

    pub fn notify_events<'a>(&self, items: impl Iterator<Item = (&'a dyn Event, &'a NodeId)>) {
        let lck = trace_read_lock!(self.inner);
        let mut by_subscription = HashMap::<u32, Vec<_>>::new();
        for (evt, notifier) in items {
            let notifier_key = MonitoredItemKeyRef {
                id: &notifier,
                attribute_id: AttributeId::EventNotifier as u32,
            };
            if let Some(items) = lck.monitored_items.get(&notifier_key) {
                for (handle, item) in items {
                    if !item.enabled {
                        continue;
                    }
                    by_subscription
                        .entry(handle.subscription_id)
                        .or_default()
                        .push((*handle, evt));
                }
            }
            // The server gets all notifications.
            let server_id: NodeId = ObjectId::Server.into();
            if notifier != &server_id {
                let server_key = MonitoredItemKeyRef {
                    id: &server_id,
                    attribute_id: AttributeId::EventNotifier as u32,
                };
                let Some(items) = lck.monitored_items.get(&server_key) else {
                    continue;
                };
                for (handle, item) in items {
                    if !item.enabled {
                        continue;
                    }
                    by_subscription
                        .entry(handle.subscription_id)
                        .or_default()
                        .push((*handle, evt));
                }
            }
        }

        for (sub_id, items) in by_subscription {
            let Some(session_id) = lck.subscription_to_session.get(&sub_id) else {
                continue;
            };
            let Some(cache) = lck.session_subscriptions.get(session_id) else {
                continue;
            };
            let mut cache_lck = cache.lock();
            cache_lck.notify_events(items);
        }
    }

    pub(crate) fn create_monitored_items(
        &self,
        session_id: u32,
        subscription_id: u32,
        requests: &[CreateMonitoredItem],
    ) -> Result<Vec<MonitoredItemCreateResult>, StatusCode> {
        let mut lck = trace_write_lock!(self.inner);
        let Some(cache) = lck.session_subscriptions.get(&session_id).cloned() else {
            return Err(StatusCode::BadNoSubscription);
        };

        let mut cache_lck = cache.lock();
        let result = cache_lck.create_monitored_items(subscription_id, requests);
        if let Ok(res) = &result {
            for (create, res) in requests.iter().zip(res.iter()) {
                if res.status_code.is_good() {
                    let key = MonitoredItemKey {
                        id: create.item_to_monitor().node_id.clone(),
                        attribute_id: create.item_to_monitor().attribute_id,
                    };

                    let index_range = create
                        .item_to_monitor()
                        .index_range
                        .as_ref()
                        .parse::<NumericRange>()
                        .unwrap_or(NumericRange::None);

                    lck.monitored_items.entry(key).or_default().insert(
                        create.handle(),
                        MonitoredItemEntry {
                            enabled: !matches!(create.monitoring_mode(), MonitoringMode::Disabled),
                            index_range,
                            data_encoding: create.item_to_monitor().data_encoding.clone(),
                        },
                    );
                }
            }
        }

        result
    }

    pub(crate) fn modify_monitored_items(
        &self,
        session_id: u32,
        subscription_id: u32,
        info: &ServerInfo,
        timestamps_to_return: TimestampsToReturn,
        requests: Vec<MonitoredItemModifyRequest>,
        type_tree: &TypeTree,
    ) -> Result<Vec<(MonitoredItemModifyResult, NodeId, u32)>, StatusCode> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        }) else {
            return Err(StatusCode::BadNoSubscription);
        };

        let mut cache_lck = cache.lock();
        cache_lck.modify_monitored_items(
            subscription_id,
            info,
            timestamps_to_return,
            requests,
            type_tree,
        )
    }

    fn get_key(session: &RwLock<Session>) -> PersistentSessionKey {
        let lck = trace_read_lock!(session);
        PersistentSessionKey::new(
            lck.user_token().unwrap(),
            lck.message_security_mode(),
            &lck.application_description().application_uri.as_ref(),
        )
    }

    pub(crate) fn set_monitoring_mode(
        &self,
        session_id: u32,
        subscription_id: u32,
        monitoring_mode: MonitoringMode,
        items: Vec<u32>,
    ) -> Result<Vec<(MonitoredItemHandle, StatusCode, NodeId, u32)>, StatusCode> {
        let mut lck = trace_write_lock!(self.inner);
        let Some(cache) = lck.session_subscriptions.get(&session_id).cloned() else {
            return Err(StatusCode::BadNoSubscription);
        };

        let mut cache_lck = cache.lock();
        let result = cache_lck.set_monitoring_mode(subscription_id, monitoring_mode, items);

        if let Ok(res) = &result {
            for (handle, status, node_id, attribute_id) in res {
                if status.is_good() {
                    let key = MonitoredItemKeyRef {
                        id: node_id,
                        attribute_id: *attribute_id,
                    };
                    if let Some(it) = lck
                        .monitored_items
                        .get_mut(&key)
                        .and_then(|it| it.get_mut(handle))
                    {
                        it.enabled = !matches!(monitoring_mode, MonitoringMode::Disabled);
                    }
                }
            }
        }
        result
    }

    pub(crate) fn set_triggering(
        &self,
        session_id: u32,
        subscription_id: u32,
        triggering_item_id: u32,
        links_to_add: Vec<u32>,
        links_to_remove: Vec<u32>,
    ) -> Result<(Vec<StatusCode>, Vec<StatusCode>), StatusCode> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        }) else {
            return Err(StatusCode::BadNoSubscription);
        };

        let mut cache_lck = cache.lock();
        cache_lck.set_triggering(
            subscription_id,
            triggering_item_id,
            links_to_add,
            links_to_remove,
        )
    }

    pub(crate) fn delete_monitored_items(
        &self,
        session_id: u32,
        subscription_id: u32,
        items: &[u32],
    ) -> Result<Vec<(MonitoredItemHandle, StatusCode, NodeId, u32)>, StatusCode> {
        let mut lck = trace_write_lock!(self.inner);
        let Some(cache) = lck.session_subscriptions.get(&session_id).cloned() else {
            return Err(StatusCode::BadNoSubscription);
        };

        let mut cache_lck = cache.lock();
        let result = cache_lck.delete_monitored_items(subscription_id, items);
        if let Ok(res) = &result {
            for (handle, status, node_id, attribute_id) in res {
                if status.is_good() {
                    let key = MonitoredItemKeyRef {
                        id: node_id,
                        attribute_id: *attribute_id,
                    };
                    if let Some(it) = lck.monitored_items.get_mut(&key) {
                        it.remove(handle);
                    }
                }
            }
        }
        result
    }

    pub(crate) fn delete_subscriptions(
        &self,
        session_id: u32,
        ids: &[u32],
    ) -> Result<Vec<(StatusCode, Vec<(MonitoredItemHandle, NodeId, u32)>)>, StatusCode> {
        let mut lck = trace_write_lock!(self.inner);
        let Some(cache) = lck.session_subscriptions.get(&session_id).cloned() else {
            return Err(StatusCode::BadNoSubscription);
        };
        let mut cache_lck = cache.lock();
        for id in ids {
            if cache_lck.contains(*id) {
                lck.subscription_to_session.remove(id);
            }
        }
        let result = cache_lck.delete_subscriptions(ids);

        for (status, item_res) in &result {
            if !status.is_good() {
                continue;
            }
            for (handle, node_id, attribute_id) in item_res {
                if *attribute_id == AttributeId::EventNotifier as u32 {
                    let key = MonitoredItemKeyRef {
                        id: node_id,
                        attribute_id: *attribute_id,
                    };
                    if let Some(it) = lck.monitored_items.get_mut(&key) {
                        it.remove(handle);
                    }
                }
            }
        }

        Ok(result)
    }

    pub(crate) fn get_session_subscription_ids(&self, session_id: u32) -> Vec<u32> {
        let Some(cache) = ({
            let lck = trace_read_lock!(self.inner);
            lck.session_subscriptions.get(&session_id).cloned()
        }) else {
            return Vec::new();
        };

        let cache_lck = cache.lock();
        cache_lck.subscription_ids()
    }

    pub(crate) fn transfer(
        &self,
        req: &TransferSubscriptionsRequest,
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
            let mut lck = trace_write_lock!(self.inner);
            let session_subs = lck
                .session_subscriptions
                .entry(session_id)
                .or_insert_with(|| {
                    Arc::new(Mutex::new(SessionSubscriptions::new(
                        self.limits,
                        key.clone(),
                    )))
                })
                .clone();
            let mut session_subs_lck = session_subs.lock();

            for (sub_id, res) in &mut results {
                let Some(inner_session_id) = lck.subscription_to_session.get(sub_id) else {
                    continue;
                };
                if session_id == *inner_session_id {
                    res.status_code = StatusCode::Good;
                    res.available_sequence_numbers =
                        session_subs_lck.available_sequence_numbers(*sub_id);
                    continue;
                }

                let Some(session_cache) = lck.session_subscriptions.get(inner_session_id).cloned()
                else {
                    continue;
                };

                let mut session_lck = session_cache.lock();

                if !session_lck.user_token().is_equivalent_for_transfer(&key) {
                    res.status_code = StatusCode::BadUserAccessDenied;
                    continue;
                }

                if let (Some(sub), notifs) = session_lck.remove(*sub_id) {
                    res.status_code = StatusCode::Good;
                    res.available_sequence_numbers =
                        Some(notifs.iter().map(|n| n.message.sequence_number).collect());

                    if let Err((e, sub, notifs)) = session_subs_lck.insert(sub, notifs) {
                        res.status_code = e;
                        let _ = session_lck.insert(sub, notifs);
                    } else {
                        if req.send_initial_values {
                            if let Some(sub) = session_subs_lck.get_mut(*sub_id) {
                                sub.set_resend_data();
                            }
                        }
                        lck.subscription_to_session.insert(*sub_id, session_id);
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
