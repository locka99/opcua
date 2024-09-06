mod monitored_item;
mod session_subscriptions;
mod subscription;

use std::{sync::Arc, time::Instant};

use chrono::Utc;
use hashbrown::{Equivalent, HashMap};
pub use monitored_item::{CreateMonitoredItem, MonitoredItem};
pub use session_subscriptions::SessionSubscriptions;
use subscription::TickReason;
pub use subscription::{MonitoredItemHandle, Subscription, SubscriptionState};

use crate::{
    core::SupportedMessage,
    sync::{Mutex, RwLock},
    types::{
        AttributeId, CreateSubscriptionRequest, CreateSubscriptionResponse, DataValue, DateTimeUtc,
        MessageSecurityMode, ModifySubscriptionRequest, ModifySubscriptionResponse,
        MonitoredItemCreateResult, MonitoredItemModifyRequest, MonitoringMode, NodeId,
        NotificationMessage, NumericRange, ObjectId, PublishRequest, QualifiedName,
        RepublishRequest, RepublishResponse, ResponseHeader, SetPublishingModeRequest,
        SetPublishingModeResponse, StatusCode, TimestampsToReturn, TransferResult,
        TransferSubscriptionsRequest, TransferSubscriptionsResponse,
    },
};

use super::{
    authenticator::UserToken,
    info::ServerInfo,
    node_manager::{
        MonitoredItemRef, MonitoredItemUpdateRef, RequestContext, ServerContext, TypeTree,
    },
    session::instance::Session,
    Event, SubscriptionLimits,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MonitoredItemKey {
    id: NodeId,
    attribute_id: AttributeId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MonitoredItemKeyRef<'a> {
    id: &'a NodeId,
    attribute_id: AttributeId,
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

/// Structure storing all subscriptions and monitored items on the server.
/// Used to notify users of changes.
///
/// Subscriptions can outlive sessions, and sessions can outlive connections,
/// so neither can be owned by the connection. This provides convenient methods for
/// manipulating subscriptions.
pub struct SubscriptionCache {
    inner: RwLock<SubscriptionCacheInner>,
    /// Configured limits on subscriptions.
    limits: SubscriptionLimits,
}

impl SubscriptionCache {
    pub(crate) fn new(limits: SubscriptionLimits) -> Self {
        Self {
            inner: RwLock::new(SubscriptionCacheInner {
                session_subscriptions: HashMap::new(),
                subscription_to_session: HashMap::new(),
                monitored_items: HashMap::new(),
            }),
            limits,
        }
    }

    /// Get the `SessionSubscriptions` object for a single session by its numeric ID.
    pub fn get_session_subscriptions(
        &self,
        session_id: u32,
    ) -> Option<Arc<Mutex<SessionSubscriptions>>> {
        let inner = trace_read_lock!(self.inner);
        inner.session_subscriptions.get(&session_id).cloned()
    }

    /// This is the periodic subscription tick where we check for
    /// triggered subscriptions.
    ///
    pub(crate) async fn periodic_tick(&self, context: &ServerContext) {
        // TODO: Look into replacing this with a smarter system, in theory it should be possible to
        // always just sleep for the exact time until the next expired publish request, which could
        // be more efficient, and would be more responsive.
        let mut to_delete = Vec::new();
        let mut items_to_delete = Vec::new();
        {
            let now = Utc::now();
            let now_instant = Instant::now();
            let lck = trace_read_lock!(self.inner);
            for (session_id, sub) in lck.session_subscriptions.iter() {
                let mut sub_lck = sub.lock();
                items_to_delete.push((
                    sub_lck.session().clone(),
                    sub_lck.tick(&now, now_instant, TickReason::TickTimerFired),
                ));
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
        if !items_to_delete.is_empty() {
            Self::delete_expired_monitored_items(context, items_to_delete).await;
        }
    }

    async fn delete_expired_monitored_items(
        context: &ServerContext,
        items_to_delete: Vec<(Arc<RwLock<Session>>, Vec<MonitoredItemRef>)>,
    ) {
        for (session, items) in items_to_delete {
            // Create a local request context, since we need to call delete monitored items.

            let (id, token) = {
                let lck = session.read();
                let Some(token) = lck.user_token() else {
                    error!("Active session missing user token, this should be impossible");
                    continue;
                };

                (lck.session_id_numeric(), token.clone())
            };
            let ctx = RequestContext {
                session,
                session_id: id,
                authenticator: context.authenticator.clone(),
                token,
                current_node_manager_index: 0,
                type_tree: context.type_tree.clone(),
                subscriptions: context.subscriptions.clone(),
                info: context.info.clone(),
            };

            for mgr in context.node_managers.iter() {
                let owned: Vec<_> = items
                    .iter()
                    .filter(|n| mgr.owns_node(n.node_id()))
                    .collect();

                if owned.is_empty() {
                    continue;
                }

                mgr.delete_monitored_items(&ctx, &owned).await;
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
        session: &Arc<RwLock<Session>>,
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
                    session.clone(),
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

    /// Notify any listening clients about a list of data changes.
    /// This can be called any time anything changes on the server, or only for values with
    /// an existing monitored item. Either way this method will deal with distributing the values
    /// to the appropriate monitored items.
    pub fn notify_data_change<'a>(
        &self,
        items: impl Iterator<Item = (DataValue, &'a NodeId, AttributeId)>,
    ) {
        let lck = trace_read_lock!(self.inner);
        let mut by_subscription: HashMap<u32, Vec<_>> = HashMap::new();
        for (dv, node_id, attribute_id) in items {
            // You can't subscribe to changes in EventNotifier, as subscribing to that value means
            // subscribing to events. Intercept any updates here, for sanity.
            if attribute_id == AttributeId::EventNotifier {
                continue;
            }

            let key = MonitoredItemKeyRef {
                id: node_id,
                attribute_id,
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
    /// This is potentially much more efficient than simply notifying blindly, but is
    /// also somewhat harder to use.
    pub fn maybe_notify<'a>(
        &self,
        items: impl Iterator<Item = (&'a NodeId, AttributeId)>,
        sample: impl Fn(&NodeId, AttributeId, &NumericRange, &QualifiedName) -> Option<DataValue>,
    ) {
        let lck = trace_read_lock!(self.inner);
        let mut by_subscription: HashMap<u32, Vec<_>> = HashMap::new();
        for (node_id, attribute_id) in items {
            if attribute_id == AttributeId::EventNotifier {
                continue;
            }

            let key = MonitoredItemKeyRef {
                id: node_id,
                attribute_id,
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

    /// Notify listening clients to events. Without a custom node manager implementing
    /// event history, this is the only way to report events in the server.
    pub fn notify_events<'a>(&self, items: impl Iterator<Item = (&'a dyn Event, &'a NodeId)>) {
        let lck = trace_read_lock!(self.inner);
        let mut by_subscription = HashMap::<u32, Vec<_>>::new();
        for (evt, notifier) in items {
            let notifier_key = MonitoredItemKeyRef {
                id: &notifier,
                attribute_id: AttributeId::EventNotifier,
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
                    attribute_id: AttributeId::EventNotifier,
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

                    let index_range = create.item_to_monitor().index_range.clone();

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
    ) -> Result<Vec<MonitoredItemUpdateRef>, StatusCode> {
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
    ) -> Result<Vec<(StatusCode, MonitoredItemRef)>, StatusCode> {
        let mut lck = trace_write_lock!(self.inner);
        let Some(cache) = lck.session_subscriptions.get(&session_id).cloned() else {
            return Err(StatusCode::BadNoSubscription);
        };

        let mut cache_lck = cache.lock();
        let result = cache_lck.set_monitoring_mode(subscription_id, monitoring_mode, items);

        if let Ok(res) = &result {
            for (status, rf) in res {
                if status.is_good() {
                    let key = MonitoredItemKeyRef {
                        id: rf.node_id(),
                        attribute_id: rf.attribute(),
                    };
                    if let Some(it) = lck
                        .monitored_items
                        .get_mut(&key)
                        .and_then(|it| it.get_mut(&rf.handle()))
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
    ) -> Result<Vec<(StatusCode, MonitoredItemRef)>, StatusCode> {
        let mut lck = trace_write_lock!(self.inner);
        let Some(cache) = lck.session_subscriptions.get(&session_id).cloned() else {
            return Err(StatusCode::BadNoSubscription);
        };

        let mut cache_lck = cache.lock();
        let result = cache_lck.delete_monitored_items(subscription_id, items);
        if let Ok(res) = &result {
            for (status, rf) in res {
                if status.is_good() {
                    let key = MonitoredItemKeyRef {
                        id: rf.node_id(),
                        attribute_id: rf.attribute(),
                    };
                    if let Some(it) = lck.monitored_items.get_mut(&key) {
                        it.remove(&rf.handle());
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
    ) -> Result<Vec<(StatusCode, Vec<MonitoredItemRef>)>, StatusCode> {
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
            for rf in item_res {
                if rf.attribute() == AttributeId::EventNotifier {
                    let key = MonitoredItemKeyRef {
                        id: rf.node_id(),
                        attribute_id: rf.attribute(),
                    };
                    if let Some(it) = lck.monitored_items.get_mut(&key) {
                        it.remove(&rf.handle());
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
        session: &Arc<RwLock<Session>>,
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
                        session.clone(),
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
