// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use opcua_types::service_types::{DataChangeNotification, EventNotificationList};

use crate::{subscription::*, subscription_timer::SubscriptionTimer};

/// Holds the live subscription state
pub struct SubscriptionState {
    /// Subscriptions (key = subscription_id)
    subscriptions: HashMap<u32, Subscription>,
    /// Subscriptions with active timers - the things that send publish requests
    subscription_timers: Vec<Arc<RwLock<SubscriptionTimer>>>,
}

impl SubscriptionState {
    pub fn new() -> SubscriptionState {
        SubscriptionState {
            subscriptions: HashMap::new(),
            subscription_timers: Vec::new(),
        }
    }

    pub(crate) fn add_subscription_timer(&mut self, timer: Arc<RwLock<SubscriptionTimer>>) {
        self.subscription_timers.push(timer);
    }

    /// Put subscription timers into a cancelled state and remove them from the subscription state
    pub(crate) fn cancel_subscription_timers(&mut self) {
        debug!("Cancelling subscription timers");
        self.subscription_timers.drain(..).for_each(|timer| {
            let mut timer = trace_write_lock_unwrap!(timer);
            debug!(
                "Cancelling subscription timer for subscription {}",
                timer.subscription_id()
            );
            timer.cancel();
        })
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
        }
    }

    pub(crate) fn delete_subscription(&mut self, subscription_id: u32) -> Option<Subscription> {
        self.subscriptions.remove(&subscription_id)
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
}
