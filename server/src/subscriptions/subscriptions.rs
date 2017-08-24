use std::collections::{HashMap, HashSet};

use time;
use chrono;

use opcua_types::*;

use DateTimeUTC;
use address_space::types::AddressSpace;
use subscriptions::{PublishRequestEntry, PublishResponseEntry};
use subscriptions::subscription::{Subscription, SubscriptionState};

const MAX_DEFAULT_PUBLISH_REQUEST_QUEUE_SIZE: usize = 100;
const MAX_PUBLISH_REQUESTS: usize = 200;
const MAX_REQUEST_TIMEOUT: i64 = 30000;

/// The publish request entry preserves the request_id which is part of the chunk layer but clients
/// are fickle about receiving responses from the same as the request. Normally this is easy because
/// request and response are synchronous, but publish requests are async, so we preserve the request_id
/// so that later we can send out responses that have the proper req id

pub struct Subscriptions {
    /// Subscriptions associated with the session
    subscriptions: HashMap<UInt32, Subscription>,
    /// The publish requeust queue (requests by the client on the session)
    pub publish_request_queue: Vec<PublishRequestEntry>,
}

impl Subscriptions {
    pub fn new() -> Subscriptions {
        Subscriptions {
            subscriptions: HashMap::new(),
            publish_request_queue: Vec::with_capacity(MAX_DEFAULT_PUBLISH_REQUEST_QUEUE_SIZE),
        }
    }

    pub fn enqueue_publish_request(&mut self, address_space: &AddressSpace, request_id: UInt32, request: PublishRequest) -> Result<Option<Vec<PublishResponseEntry>>, StatusCode> {
        let max_publish_requests = MAX_PUBLISH_REQUESTS;
        if self.publish_request_queue.len() >= max_publish_requests {
            error!("Too many publish requests, throwing it away");
            Err(BAD_TOO_MANY_PUBLISH_REQUESTS)
        } else {
            trace!("Sending a tick to subscriptions to deal with the request");
            self.publish_request_queue.insert(0, PublishRequestEntry {
                request_id,
                request,
            });
            Ok(self.tick(true, address_space))
        }
    }

    pub fn len(&self) -> usize {
        self.subscriptions.len()
    }

    pub fn contains(&self, subscription_id: UInt32) -> bool {
        self.subscriptions.contains_key(&subscription_id)
    }

    pub fn insert(&mut self, subscription_id: UInt32, subscription: Subscription) {
        self.subscriptions.insert(subscription_id, subscription);
    }

    pub fn remove(&mut self, subscription_id: UInt32) -> Option<Subscription> {
        self.subscriptions.remove(&subscription_id)
    }

    pub fn get_mut(&mut self, subscription_id: UInt32) -> Option<&mut Subscription> {
        self.subscriptions.get_mut(&subscription_id)
    }

    /// Iterates through the existing queued publish requests and creates a timeout
    /// publish response any that have expired.
    pub fn expire_stale_publish_requests(&mut self, now: &DateTimeUTC) -> Option<Vec<PublishResponseEntry>> {
        if self.publish_request_queue.is_empty() {
            return None;
        }

        // Look for publish requests that have expired
        let mut expired_request_handles = HashSet::with_capacity(self.publish_request_queue.len());
        let mut expired_requests = Vec::with_capacity(self.publish_request_queue.len());

        for request in self.publish_request_queue.iter() {
            let request_header = &request.request.request_header;
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
                expired_request_handles.insert(request_header.request_handle);
                expired_requests.push(request.clone());
            }
        }

        if expired_request_handles.is_empty() {
            return None;
        }

        // Remove the expired requests (if any)
        self.publish_request_queue.retain(|ref r| {
            !expired_request_handles.contains(&r.request.request_header.request_handle)
        });

        // Make publish responses for each expired request
        let mut publish_responses = Vec::with_capacity(expired_requests.len());
        for expired_request in expired_requests {
            let now = DateTime::from_chrono(now);
            publish_responses.push(PublishResponseEntry {
                request_id: expired_request.request_id,
                response: SupportedMessage::ServiceFault(ServiceFault {
                    response_header: ResponseHeader::new_timestamped_service_result(now.clone(), &expired_request.request.request_header, BAD_REQUEST_TIMEOUT),
                }),
            });
        }
        if !publish_responses.is_empty() {
            Some(publish_responses)
        } else {
            None
        }
    }

    /// Iterate all subscriptions calling tick on each. Note this could potentially be done to run in parallel
    /// assuming the action to clean dead subscriptions was a join done after all ticks had completed.
    pub fn tick(&mut self, receive_publish_request: bool, address_space: &AddressSpace) -> Option<Vec<PublishResponseEntry>> {
        let now = chrono::UTC::now();

        let mut publish_request_queue = self.publish_request_queue.clone();

        let mut request_response_results = Vec::with_capacity(publish_request_queue.len());
        let mut dead_subscriptions: Vec<u32> = Vec::with_capacity(self.subscriptions.len());

        // Iterate through all subscriptions. If there is a publish request it will be used to
        // acknowledge notifications and the response to return new notifications.

        let mut acknowledge_results_map = HashMap::new();
        for publish_request in publish_request_queue.iter() {
            let acknowledge_results = self.process_subscription_acknowledgements(publish_request);
            acknowledge_results_map.insert(publish_request.request_id, acknowledge_results);
        }

        // Now tick over the subscriptions
        for (subscription_id, subscription) in self.subscriptions.iter_mut() {
            // Dead subscriptions will be removed at the end
            if subscription.state == SubscriptionState::Closed {
                dead_subscriptions.push(*subscription_id);
            } else {
                let publish_request = publish_request_queue.pop();
                let publishing_req_queued = publish_request_queue.len() > 0 || publish_request.is_some();

                // Now tick the subscription to see if it has any notifications. If there are
                // notifications then the publish response will be associated with his subscription
                // and ready to go.
                let (publish_response, update_state_result) = subscription.tick(address_space, receive_publish_request, &publish_request, publishing_req_queued, &now);
                if let Some(mut publish_response) = publish_response {
                    if let SupportedMessage::PublishResponse(ref mut response) = publish_response.response {
                        let request_id = publish_response.request_id;
                        trace!("Publish response for request {} is being queued for subscription{}", request_id, subscription_id);
                        if let Some(acknowledge_results) = acknowledge_results_map.remove(&request_id) {
                            // Consume the notifications
                            response.results = acknowledge_results;
                        }
                    } else {
                        panic!("Expecting publish response");
                    }
                    request_response_results.push(publish_response);
                } else if publish_request.is_some() {
                    let publish_request = publish_request.unwrap();
                    trace!("Publish request {} was unused by subscription {} and is being requeued", publish_request.request_id, subscription_id);
                    publish_request_queue.push(publish_request);
                }
            }
        }

        // Remove dead subscriptions
        for subscription_id in dead_subscriptions {
            self.subscriptions.remove(&subscription_id);
        }

        // Check for any publish requests which weren't handled already
        publish_request_queue.retain(|ref publish_request| {
            let request_id = publish_request.request_id;
            if let Some(acknowledge_results) = acknowledge_results_map.remove(&request_id) {
                trace!("Publish request {} is being used to return notifications", request_id);
                let now = DateTime::now();
                request_response_results.push(PublishResponseEntry {
                    request_id: publish_request.request_id,
                    response: SupportedMessage::PublishResponse(PublishResponse {
                        response_header: ResponseHeader::new_timestamped_service_result(now.clone(), &publish_request.request.request_header, GOOD),
                        subscription_id: 0,
                        available_sequence_numbers: None,
                        more_notifications: false,
                        notification_message: NotificationMessage {
                            sequence_number: 0,
                            publish_time: now.clone(),
                            notification_data: None,
                        },
                        results: acknowledge_results,
                        diagnostic_infos: None,
                    })
                });
                false
            } else {
                true
            }
        });

        // Update modified queue
        self.publish_request_queue = publish_request_queue;

        if request_response_results.is_empty() {
            None
        } else {
            Some(request_response_results)
        }
    }

    /// Deletes the acknowledged notifications, returning a list of status code for each according
    /// to whether it was found or not.
    ///
    /// GOOD - deleted notification
    /// BAD_SUBSCRIPTION_ID_INVALID - Subscription doesn't exist
    /// BAD_SEQUENCE_NUMBER_UNKNOWN - Sequence number doesn't exist
    ///
    fn process_subscription_acknowledgements(&mut self, request: &PublishRequestEntry) -> Option<Vec<StatusCode>> {
        trace!("Processing subscription acknowledgements");
        let request = &request.request;
        if request.subscription_acknowledgements.is_some() {
            let subscription_acknowledgements = request.subscription_acknowledgements.as_ref().unwrap();
            let mut results: Vec<StatusCode> = Vec::with_capacity(subscription_acknowledgements.len());
            for subscription_acknowledgement in subscription_acknowledgements {
                let subscription_id = subscription_acknowledgement.subscription_id;
                let subscription = self.subscriptions.get_mut(&subscription_id);
                let result = if subscription.is_none() {
                    BAD_SUBSCRIPTION_ID_INVALID
                } else {
                    subscription.unwrap().delete_acked_notification_msg(subscription_acknowledgement)
                };
                results.push(result);
            }
            Some(results)
        } else {
            None
        }
    }
}