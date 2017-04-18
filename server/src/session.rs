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

/// The publish request entry preserves the request_id which is part of the chunk layer but clients
/// are fickle about receiving responses from the same as the request. Normally this is easy because
/// request and response are synchronous, but publish requests are async, so we preserve the request_id
/// so that later we can send out responses that have the proper req id
#[derive(Clone)]
pub struct PublishRequestEntry {
    pub request_id: UInt32,
    pub request: PublishRequest,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PublishResponseEntry {
    pub request_id: UInt32,
    pub response: PublishResponse,
}

/// Session info holds information about a session created by CreateSession service
#[derive(Clone)]
pub struct SessionInfo {}

/// Session state is anything associated with the session at the message / service level
#[derive(Clone)]
pub struct SessionState {
    pub subscriptions: Arc<Mutex<HashMap<UInt32, Subscription>>>,
    pub publish_request_queue: Vec<PublishRequestEntry>,

    pub session_id: NodeId,
    pub activated: bool,
    pub authentication_token: NodeId,
    pub session_timeout: Double,
    pub user_identity: Option<ExtensionObject>,
    pub max_request_message_size: UInt32,
    pub max_response_message_size: UInt32,
    pub endpoint_url: UAString,

    last_session_id: UInt32,
}

impl SessionState {
    pub fn new() -> SessionState {
        SessionState {
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
            publish_request_queue: Vec::with_capacity(MAX_DEFAULT_PUBLISH_REQUEST_QUEUE_SIZE),
            session_id: NodeId::null(),
            activated: false,
            authentication_token: NodeId::null(),
            session_timeout: 0f64,
            user_identity: None,
            max_request_message_size: 0,
            max_response_message_size: 0,
            endpoint_url: UAString::null(),
            last_session_id: 0,
        }
    }

    pub fn next_session_id(&mut self) -> NodeId {
        self.last_session_id += 1;
        NodeId::new_numeric(1, self.last_session_id as u64)
    }

    pub fn enqueue_publish_request(&mut self, server_state: &mut ServerState, request_id: UInt32, request: PublishRequest) -> Result<Option<Vec<PublishResponseEntry>>, StatusCode> {
        let max_publish_requests = MAX_PUBLISH_REQUESTS;
        if self.publish_request_queue.len() >= max_publish_requests {
            error!("Too many publish requests, throwing it away");
            Err(BAD_TOO_MANY_PUBLISH_REQUESTS)
        } else {
            info!("Sending a tick to subscriptions to deal with the request");
            self.publish_request_queue.insert(0, PublishRequestEntry {
                request_id: request_id,
                request: request,
            });
            let address_space = server_state.address_space.lock().unwrap();
            Ok(self.tick_subscriptions(true, &address_space))
        }
    }

    /// Iterate all subscriptions calling tick on each. Note this could potentially be done to run in parallel
    /// assuming the action to clean dead subscriptions was a join done after all ticks had completed.
    pub fn tick_subscriptions(&mut self, receive_publish_request: bool, address_space: &AddressSpace) -> Option<Vec<PublishResponseEntry>> {
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
                    let publish_request = self.publish_request_queue.pop();
                    let publishing_req_queued = self.publish_request_queue.len() > 0 || publish_request.is_some();

                    let (publish_response, update_state_result) = subscription.tick(address_space, receive_publish_request, &publish_request, publishing_req_queued, &now);
                    if let Some(update_state_result) = update_state_result {
                        if let Some(publish_response) = publish_response {
                            debug!("Queuing a publish response {:?}", publish_response);
                            result.push(publish_response);
                        }
                        // Determine if publish request should be dequeued (after processing all subscriptions)
                        match update_state_result.publish_request_action {
                            PublishRequestAction::Dequeue => {
                                debug!("PublishRequestAction::Dequeue");
                            }
                            PublishRequestAction::Enqueue => {
                                debug!("PublishRequestAction::Enqueue");
                                if publish_request.is_none() {
                                    panic!("Should not have an enqueue response when there was no publish request");
                                }
                                self.publish_request_queue.push(publish_request.unwrap());
                            }
                            _ => {
                                if publish_request.is_some() {
                                    debug!("PublishRequestAction::None (but re-enqueuing publish request)");
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

    /// Iterates through the existing queued publish requests and creates a timeout
    /// publish response any that have expired.
    pub fn expire_stale_publish_requests(&mut self, now: &DateTimeUTC) -> Option<Vec<PublishResponseEntry>> {
        let mut expired = Vec::with_capacity(self.publish_request_queue.len());

        // Strip out publish requests which have expired
        self.publish_request_queue.retain(|ref r| {
            let request_header = &r.request.request_header;
            let timestamp: DateTimeUTC = request_header.timestamp.as_chrono();
            let timeout = if request_header.timeout_hint > 0 && (request_header.timeout_hint as i64) < MAX_REQUEST_TIMEOUT {
                request_header.timeout_hint as i64
            } else {
                MAX_REQUEST_TIMEOUT
            };
            let timeout_d = time::Duration::milliseconds(timeout);

            // The request has timed out if the timestamp plus hint exceeds the input time
            let expiration_time = timestamp + timeout_d;
            if *now >= expiration_time {
                debug!("Publish request {} has expired - timestamp = {:?}, expiration hint = {}, expiration time = {:?}, time now = {:?}, ", request_header.request_handle, timestamp, timeout, expiration_time, now);
                let now = DateTime::from_chrono(now);
                expired.push(PublishResponseEntry {
                    request_id: r.request_id,
                    response: PublishResponse {
                        response_header: ResponseHeader::new_service_result(&now, request_header, BAD_REQUEST_TIMEOUT),
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
                    },
                });
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
