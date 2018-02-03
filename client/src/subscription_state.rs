use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use time;
use timer;

use opcua_types::UInt32;
use opcua_types::status_codes::StatusCode;

use session::Session;
use subscription::*;

pub struct SubscriptionState {
    /// Subscriptions
    pub subscriptions: HashMap<UInt32, Subscription>,
    /// Subscription timer
    pub subscription_timer: Option<(timer::Timer, timer::Guard)>,
}

impl SubscriptionState {
    pub fn new() -> SubscriptionState {
        SubscriptionState {
            subscriptions: HashMap::new(),
            subscription_timer: None,
        }
    }

    fn subscription_timer(session: &mut Session) {

        // On timer, send a publish request with optional
        //   Acknowledgements
        let subscription_acknowledgements = Vec::new();

        // Receive response
        match session.publish(subscription_acknowledgements) {
            Ok(response) => {
                // Update subscriptions based on response
                // Queue acknowledgements for next request

                let notification_message = response.notification_message;
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
