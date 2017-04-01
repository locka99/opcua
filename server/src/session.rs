use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use time;
use chrono;

use prelude::*;

use DateTimeUTC;
use subscriptions::*;

const MAX_DEFAULT_PUBLISH_REQUEST_QUEUE_SIZE: usize = 100;
const MAX_PUBLISH_REQUESTS: usize = 200;
const MAX_REQUEST_TIMEOUT: i64 = 30000;

/// Session info holds information about a session created by CreateSession service
#[derive(Clone)]
pub struct SessionInfo {}

/// Session state is anything associated with the session at the message / service level
#[derive(Clone)]
pub struct SessionState {
    pub session_info: Option<SessionInfo>,
    pub subscriptions: Arc<Mutex<HashMap<UInt32, Subscription>>>,
    pub publish_request_queue: Vec<PublishRequest>,
}

impl SessionState {
    pub fn new() -> SessionState {
        SessionState {
            session_info: None,
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
            publish_request_queue: Vec::with_capacity(MAX_DEFAULT_PUBLISH_REQUEST_QUEUE_SIZE),
        }
    }

    pub fn enqueue_publish_request(&mut self, server_state: &mut ServerState, request: PublishRequest) -> Result<Option<Vec<SupportedMessage>>, &'static StatusCode> {
        let max_publish_requests = MAX_PUBLISH_REQUESTS;
        if self.publish_request_queue.len() >= max_publish_requests {
            error!("Too many publish requests, throwing it away");
            Err(&BAD_TOO_MANY_PUBLISH_REQUESTS)
        } else {
            info!("Sending a tick to subscriptions to deal with the request");
            let address_space = server_state.address_space.lock().unwrap();
            Ok(self.tick_subscriptions(&address_space))
        }
    }

    /// Iterate all subscriptions calling tick on each. Note this could potentially be done to run in parallel
    /// assuming the action to clean dead subscriptions was a join done after all ticks had completed.
    pub fn tick_subscriptions(&mut self, address_space: &AddressSpace) -> Option<Vec<SupportedMessage>> {
        let mut result = Vec::new();
        let now = chrono::UTC::now();

        {
            let mut subscriptions = self.subscriptions.lock().unwrap();
            let mut dead_subscriptions: Vec<u32> = Vec::with_capacity(subscriptions.len());

            for (subscription_id, subscription) in subscriptions.iter_mut() {
                // Dead subscriptions will be removed at the end
                if subscription.state == SubscriptionState::Closed {
                    dead_subscriptions.push(*subscription_id);
                } else {
                    let publishing_req_queued = self.publish_request_queue.len() > 0;
                    let publish_request = self.publish_request_queue.pop();

                    let (notification_message, update_state_result) = subscription.tick(address_space, &publish_request, publishing_req_queued, &now);
                    if let Some(update_state_result) = update_state_result {
                        if let Some(notification_message) = notification_message {
                            let publish_response = PublishResponse {
                                response_header: ResponseHeader::new_notification_response(&DateTime::now(), &GOOD),
                                subscription_id: *subscription_id,
                                available_sequence_numbers: None,
                                // TODO
                                more_notifications: subscription.more_notifications,
                                notification_message: notification_message,
                                results: Some(update_state_result.acknowledge_results),
                                diagnostic_infos: None,
                            };
                            error!("queuing a publish response {:?}", publish_response);
                            result.push(SupportedMessage::PublishResponse(publish_response));
                        }
                        // Determine if publish request should be dequeued (after processing all subscriptions)
                        match update_state_result.publish_request_action {
                            PublishRequestAction::Dequeue => {}
                            PublishRequestAction::Enqueue => {
                                if publish_request.is_none() {
                                    panic!("Should not have an enqueue response when there was no publish request");
                                }
                                self.publish_request_queue.push(publish_request.unwrap());
                            }
                            _ => {
                                if publish_request.is_some() {
                                    self.publish_request_queue.push(publish_request.unwrap());
                                }
                            }
                        }
                    }
                }
            }

            // Remove dead subscriptions
            for subscription_id in dead_subscriptions {
                subscriptions.remove(&subscription_id);
            }
        }

        if result.is_empty() { None } else { Some(result) }
    }


    pub fn expire_stale_publish_requests(&mut self, now: &DateTimeUTC) -> Option<Vec<SupportedMessage>> {
        let mut expired = Vec::with_capacity(self.publish_request_queue.len());

        // Strip out publish requests which have expired
        self.publish_request_queue.retain(|ref r| {
            let timestamp: DateTimeUTC = r.request_header.timestamp.as_chrono();
            let timeout = if r.request_header.timeout_hint > 0 && (r.request_header.timeout_hint as i64) < MAX_REQUEST_TIMEOUT {
                r.request_header.timeout_hint as i64
            } else {
                MAX_REQUEST_TIMEOUT
            };
            let timeout_d = time::Duration::milliseconds(timeout);

            // The request has timed out if the timestamp plus hint exceeds the input time
            let expiration_time = timestamp + timeout_d;
            if *now >= expiration_time {
                debug!("Publish request {} has expired - timestamp = {:?}, expiration hint = {}, expiration time = {:?}, time now = {:?}, ", r.request_header.request_handle, timestamp, timeout, expiration_time, now);
                let now = DateTime::from_chrono(now);
                let response = PublishResponse {
                    response_header: ResponseHeader::new_service_result(&now, &r.request_header, &BAD_REQUEST_TIMEOUT),
                    subscription_id: 0,
                    available_sequence_numbers: None,
                    more_notifications: false,
                    notification_message: NotificationMessage {
                        sequence_number: 0,
                        publish_time: now.clone(),
                        notification_data: None
                    },
                    results: None,
                    diagnostic_infos: None
                };
                expired.push(SupportedMessage::PublishResponse(response));
                // Remove
                false
            } else {
                // Keep
                true
            }
        });
        if !expired.is_empty() {
            Some(expired)
        } else {
            None
        }
    }
}
