use opcua_types::{Byte, Double, UInt32};
use opcua_types::service_types::SubscriptionAcknowledgement;
use opcua_types::status_codes::StatusCode;
use session::Session;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use subscription::*;
use time;
use timer;

pub struct SubscriptionState {
    /// Unacknowledged
    subscription_acknowledgements: Vec<SubscriptionAcknowledgement>,
    /// Subscriptions (key = subscription_id)
    subscriptions: HashMap<UInt32, Subscription>,
    /// Subscription timer
    pub subscription_timer: Option<(timer::Timer, timer::Guard)>,
}

impl SubscriptionState {
    pub fn new() -> SubscriptionState {
        SubscriptionState {
            subscription_acknowledgements: Vec::new(),
            subscriptions: HashMap::new(),
            subscription_timer: None,
        }
    }

    pub fn subscription_exists(&self, subscription_id: UInt32) -> bool {
        self.subscriptions.contains_key(&subscription_id)
    }

    pub fn add_subscription(&mut self, subscription: Subscription) {
        self.subscriptions.insert(subscription.subscription_id(), subscription);
    }

    pub fn modify_subscription(&mut self, subscription_id: UInt32, publishing_interval: Double, lifetime_count: UInt32, max_keep_alive_count: UInt32, max_notifications_per_publish: UInt32, priority: Byte) {
        if let Some(ref mut subscription) = self.subscriptions.get_mut(&subscription_id) {
            subscription.set_publishing_interval(publishing_interval);
            subscription.set_lifetime_count(lifetime_count);
            subscription.set_max_keep_alive_count(max_keep_alive_count);
            subscription.set_max_notifications_per_publish(max_notifications_per_publish);
            subscription.set_priority(priority);
        }
    }

    pub fn insert_monitored_items(&mut self, subscription_id: UInt32, items_to_create: Vec<CreateMonitoredItem>) {
        if let Some(ref mut subscription) = self.subscriptions.get_mut(&subscription_id) {
            subscription.insert_monitored_items(items_to_create);
        }
    }

    pub fn modify_monitored_items(&mut self, subscription_id: UInt32, items_to_modify: Vec<ModifyMonitoredItem>) {
        if let Some(ref mut subscription) = self.subscriptions.get_mut(&subscription_id) {
            subscription.modify_monitored_items(items_to_modify);
        }
    }

    pub fn delete_monitored_items(&mut self, subscription_id: UInt32, items_to_delete: Vec<UInt32>) {
        if let Some(ref mut subscription) = self.subscriptions.get_mut(&subscription_id) {
            subscription.delete_monitored_items(items_to_delete);
        }
    }

    pub fn delete_subscription(&mut self, subscription_id: UInt32) {
        self.subscriptions.remove(&subscription_id);
    }

    fn subscription_timer(session: &mut Session) {
        if !session.subscription_state.subscriptions.is_empty() {
            // On timer, send a publish request with optional
            //   Acknowledgements
            let subscription_acknowledgements = session.subscription_state.subscription_acknowledgements.drain(..).collect();

            // Receive response
            match session.publish(subscription_acknowledgements) {
                Ok(response) => {
                    // Update subscriptions based on response

                    // Queue acknowledgements for next request
                    let notification_message = response.notification_message;

                    // Queue an acknowledgement for this request
                    session.subscription_state.subscription_acknowledgements.push(SubscriptionAcknowledgement {
                        subscription_id: response.subscription_id,
                        sequence_number: notification_message.sequence_number,
                    });

                    // Process data change notifications
                    let data_change_notifications = notification_message.data_change_notifications();
                    data_change_notifications.iter().for_each(|n| {
                        if let Some(ref monitored_items) = n.monitored_items {
                            monitored_items.iter().for_each(|i| {
                                if i.client_handle == 1000 {
                                    // TODO
                                    trace!("xxxx");
                                }
                                // use i.client_handle to find monitored item and store i.value
                            });
                        }
                    });

                    //pub available_sequence_numbers: Option<Vec<UInt32>>,
                    //pub more_notifications: Boolean,
                    //pub notification_message: NotificationMessage,
                    //pub results: Option<Vec<StatusCode>>,
                    //pub diagnostic_infos: Option<Vec<DiagnosticInfo>>,
                }
                Err(status_code) => {
                    // Terminate timer if
                    match status_code {
                        StatusCode::BadSessionIdInvalid => {
                            //   BadSessionIdInvalid
                            trace!("Subscription timer received BadSessionIdInvalid error code");
                        }
                        StatusCode::BadNoSubscription => {
                            //   BadNoSubscription
                            trace!("Subscription timer received BadNoSubscription error code");
                        }
                        StatusCode::BadTooManyPublishRequests => {
                            //   BadTooManyPublishRequests
                            trace!("Subscription timer received BadTooManyPublishRequests error code");
                        }
                        _ => {
                            trace!("Subscription timer received error code {:?}", status_code);
                        }
                    }
                }
            }
        }
    }

    const SUBSCRIPTION_TIMER_INTERVAL: i64 = 50i64;

    /// The subscriptions timer is the thing that will send publish requests in the background to
    /// service any active subscriptions the client has created.
    pub fn init_subscriptions_timer(&mut self, session: Arc<Mutex<Session>>) {
        // Publish timer will continuously issue publish requests to the server
        if self.subscription_timer.is_none() {
            let timer = {
                let timer = timer::Timer::new();
                let timer_guard = timer.schedule_repeating(time::Duration::milliseconds(SubscriptionState::SUBSCRIPTION_TIMER_INTERVAL), move || {
                    let mut session = session.lock().unwrap();
                    SubscriptionState::subscription_timer(&mut session);
                });
                (timer, timer_guard)
            };

            self.subscription_timer = Some((timer.0, timer.1));
        }
    }
}
