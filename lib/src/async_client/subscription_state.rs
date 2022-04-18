// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::collections::HashMap;

use tokio::time::Instant;

use crate::types::service_types::{DataChangeNotification, EventNotificationList};

use super::subscription::*;

/// Holds the live subscription state
pub struct SubscriptionState {
    /// Subscripion keep alive timeout
    keep_alive_timeout: Option<u64>,
    /// Timestamp of last pushish request
    last_publish_request: Instant,
    /// Subscriptions (key = subscription_id)
    subscriptions: HashMap<u32, Subscription>,
}

impl SubscriptionState {
    pub fn new() -> SubscriptionState {
        SubscriptionState {
            keep_alive_timeout: None,
            last_publish_request: Instant::now(),
            subscriptions: HashMap::new(),
        }
    }

    pub fn subscription_ids(&self) -> Option<Vec<u32>> {
        if self.subscriptions.is_empty() {
            None
        } else {
            Some(self.subscriptions.keys().cloned().collect())
        }
    }

    pub fn subscription_exists(&self, subscription_id: u32) -> bool {
        self.subscriptions.contains_key(&subscription_id)
    }

    pub fn get(&self, subscription_id: u32) -> Option<&Subscription> {
        self.subscriptions.get(&subscription_id)
    }

    pub(crate) fn add_subscription(&mut self, subscription: Subscription) {
        self.subscriptions
            .insert(subscription.subscription_id(), subscription);
        self.set_keep_alive_timeout();
    }

    pub(crate) fn modify_subscription(
        &mut self,
        subscription_id: u32,
        publishing_interval: f64,
        lifetime_count: u32,
        max_keep_alive_count: u32,
        max_notifications_per_publish: u32,
        priority: u8,
    ) {
        if let Some(ref mut subscription) = self.subscriptions.get_mut(&subscription_id) {
            subscription.set_publishing_interval(publishing_interval);
            subscription.set_lifetime_count(lifetime_count);
            subscription.set_max_keep_alive_count(max_keep_alive_count);
            subscription.set_max_notifications_per_publish(max_notifications_per_publish);
            subscription.set_priority(priority);
            self.set_keep_alive_timeout();
        }
    }

    pub(crate) fn delete_subscription(&mut self, subscription_id: u32) -> Option<Subscription> {
        let subscription = self.subscriptions.remove(&subscription_id);
        self.set_keep_alive_timeout();
        subscription
    }

    pub(crate) fn set_publishing_mode(
        &mut self,
        subscription_ids: &[u32],
        publishing_enabled: bool,
    ) {
        subscription_ids.iter().for_each(|subscription_id| {
            if let Some(ref mut subscription) = self.subscriptions.get_mut(subscription_id) {
                subscription.set_publishing_enabled(publishing_enabled);
            }
        });
    }

    pub(crate) fn on_data_change(
        &mut self,
        subscription_id: u32,
        data_change_notifications: &[DataChangeNotification],
    ) {
        if let Some(ref mut subscription) = self.subscriptions.get_mut(&subscription_id) {
            subscription.on_data_change(data_change_notifications);
        }
    }

    pub(crate) fn on_event(&mut self, subscription_id: u32, events: &[EventNotificationList]) {
        if let Some(ref mut subscription) = self.subscriptions.get_mut(&subscription_id) {
            subscription.on_event(events);
        }
    }

    pub(crate) fn insert_monitored_items(
        &mut self,
        subscription_id: u32,
        items_to_create: &[CreateMonitoredItem],
    ) {
        if let Some(ref mut subscription) = self.subscriptions.get_mut(&subscription_id) {
            subscription.insert_monitored_items(items_to_create);
        }
    }

    pub(crate) fn modify_monitored_items(
        &mut self,
        subscription_id: u32,
        items_to_modify: &[ModifyMonitoredItem],
    ) {
        if let Some(ref mut subscription) = self.subscriptions.get_mut(&subscription_id) {
            subscription.modify_monitored_items(items_to_modify);
        }
    }

    pub(crate) fn delete_monitored_items(&mut self, subscription_id: u32, items_to_delete: &[u32]) {
        if let Some(ref mut subscription) = self.subscriptions.get_mut(&subscription_id) {
            subscription.delete_monitored_items(items_to_delete);
        }
    }

    pub(crate) fn set_triggering(
        &mut self,
        subscription_id: u32,
        triggering_item_id: u32,
        links_to_add: &[u32],
        links_to_remove: &[u32],
    ) {
        if let Some(ref mut subscription) = self.subscriptions.get_mut(&subscription_id) {
            subscription.set_triggering(triggering_item_id, links_to_add, links_to_remove);
        }
    }

    pub(crate) fn last_publish_request(&self) -> Instant {
        self.last_publish_request
    }

    pub(crate) fn set_last_publish_request(&mut self, now: Instant) {
        self.last_publish_request = now;
    }

    pub(crate) fn keep_alive_timeout(&self) -> Option<u64> {
        self.keep_alive_timeout
    }

    fn set_keep_alive_timeout(&mut self) {
        self.keep_alive_timeout = self
            .subscriptions
            .values()
            .map(|v| (v.publishing_interval() * v.lifetime_count() as f64).floor() as u64)
            .min()
    }
}
