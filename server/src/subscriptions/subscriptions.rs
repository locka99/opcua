use std::collections::{HashMap, VecDeque};

use time;
use chrono;

use opcua_types::*;
use opcua_types::StatusCode::*;

use DateTimeUtc;
use address_space::types::AddressSpace;
use subscriptions::{PublishRequestEntry, PublishResponseEntry};
use subscriptions::subscription::{Subscription, SubscriptionState};

pub struct Subscriptions {
    // Timeout period for requests in ms
    publish_request_timeout: i64,
    /// Subscriptions associated with the session
    subscriptions: HashMap<UInt32, Subscription>,
    /// Maximum number of publish requests
    max_publish_requests: usize,
    /// The publish request queue (requests by the client on the session)
    pub publish_request_queue: VecDeque<PublishRequestEntry>,
    /// The publish response queue
    pub publish_response_queue: Vec<PublishResponseEntry>,
}

impl Subscriptions {
    pub fn new(max_publish_requests: usize, publish_request_timeout: i64) -> Subscriptions {
        Subscriptions {
            publish_request_timeout,
            subscriptions: HashMap::new(),
            max_publish_requests,
            publish_request_queue: VecDeque::with_capacity(max_publish_requests),
            publish_response_queue: Vec::with_capacity(max_publish_requests),
        }
    }

    /// Places a new publish request onto the queue of publish requests.
    ///
    /// If the queue is full this call will pop the oldest and generate a service fault
    /// for that before pushing the new one.
    pub fn enqueue_publish_request(&mut self, _: &AddressSpace, request_id: UInt32, request: PublishRequest) -> Result<(), StatusCode> {

        // TODO we need to check subscriptions here that are waiting to publish, starting with the
        // one waiting longest / priority
        //
        // If there is no waiting subscription waiting to publish, the request shall be queued
        // including expiring old requests and returning the BadTooManyPublishRequests if
        // there are too many
        //
        // else get the subscription ready to publish

        // Check if we have too many requests already
        if self.publish_request_queue.len() >= self.max_publish_requests {
            error!("Too many publish requests {} for capacity {}, throwing oldest away", self.publish_request_queue.len(), self.max_publish_requests);
            let oldest_publish_request = self.publish_request_queue.pop_back().unwrap();
            Err(BadTooManyPublishRequests)
        } else {
            // Add to the start of the queue - older items are popped from the end
            self.publish_request_queue.push_front(PublishRequestEntry {
                request_id,
                request,
            });
            Ok(())
        }
    }

    pub fn dequeue_publish_request(&mut self) -> Option<PublishRequestEntry> {
        self.publish_request_queue.pop_back()
    }

    pub fn is_empty(&self) -> bool {
        self.subscriptions.is_empty()
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
    pub fn expire_stale_publish_requests(&mut self, now: &DateTimeUtc) {
        if self.publish_request_queue.is_empty() {
            return;
        }

        let mut publish_responses = Vec::with_capacity(self.publish_request_queue.len());

        // Remove publish requests that have expired
        let publish_request_timeout = self.publish_request_timeout;
        self.publish_request_queue.retain(|ref request| {
            let request_header = &request.request.request_header;
            let timestamp: DateTimeUtc = request_header.timestamp.clone().into();
            let timeout = if request_header.timeout_hint > 0 && (request_header.timeout_hint as i64) < publish_request_timeout {
                request_header.timeout_hint as i64
            } else {
                publish_request_timeout
            };
            let timeout_d = time::Duration::milliseconds(timeout);
            // The request has timed out if the timestamp plus hint exceeds the input time
            let expiration_time = timestamp + timeout_d;
            if *now >= expiration_time {
                debug!("Publish request {} has expired - timestamp = {:?}, expiration hint = {}, expiration time = {:?}, time now = {:?}, ", request_header.request_handle, timestamp, timeout, expiration_time, now);
                publish_responses.push(PublishResponseEntry {
                    request_id: request.request_id,
                    response: SupportedMessage::ServiceFault(ServiceFault {
                        response_header: ResponseHeader::new_timestamped_service_result(DateTime::now(), &request.request.request_header, BadTimeout),
                    }),
                });
                false
            } else {
                true
            }
        });
        // Queue responses for each expired request
        self.publish_response_queue.append(&mut publish_responses);
    }

    /// Iterate all subscriptions calling tick on each. Note this could potentially be done to run in parallel
    /// assuming the action to clean dead subscriptions was a join done after all ticks had completed.
    pub fn tick(&mut self, receive_publish_request: bool, address_space: &AddressSpace) -> Result<(), StatusCode> {
        let now = chrono::Utc::now();

        let mut publish_request_queue = self.publish_request_queue.clone();

        let mut handled_requests = Vec::with_capacity(publish_request_queue.len());
        let mut publish_responses = Vec::with_capacity(publish_request_queue.len());

        let mut dead_subscriptions: Vec<u32> = Vec::with_capacity(self.subscriptions.len());

        // Iterate through all subscriptions. If there is a publish request it will be used to
        // acknowledge notifications and the response to return new notifications.

        // Now tick over the subscriptions
        for (subscription_id, subscription) in &mut self.subscriptions {
            // Dead subscriptions will be removed at the end
            if subscription.state == SubscriptionState::Closed {
                dead_subscriptions.push(*subscription_id);
            } else {
                let publish_request = publish_request_queue.pop_back();
                let publishing_req_queued = !publish_request_queue.is_empty() || publish_request.is_some();

                // Now tick the subscription to see if it has any notifications. If there are
                // notifications then the publish response will be associated with his subscription
                // and ready to go.
                let (publish_response, _) = subscription.tick(address_space, receive_publish_request, &publish_request, publishing_req_queued, &now);
                if let Some(publish_response) = publish_response {
                    // Process the acknowledgements for the request
                    publish_responses.push(publish_response);
                    handled_requests.push(publish_request.unwrap())
                } else if publish_request.is_some() {
                    let publish_request = publish_request.unwrap();
                    trace!("Publish request {} was unused by subscription {} and is being requeued", publish_request.request_id, subscription_id);
                    publish_request_queue.push_back(publish_request);
                }
            }
        }

        // Handle the acknowledgements in the request
        for (idx, publish_request) in handled_requests.iter().enumerate() {
            let publish_response = publish_responses.get_mut(idx).unwrap();
            if let SupportedMessage::PublishResponse(ref mut publish_response) = publish_response.response {
                publish_response.results = self.process_subscription_acknowledgements(publish_request);
            }
        }

        // Remove dead subscriptions
        for subscription_id in dead_subscriptions {
            self.subscriptions.remove(&subscription_id);
        }

        // Update request and response queue
        self.publish_request_queue = publish_request_queue;
        self.publish_response_queue.append(&mut publish_responses);

        Ok(())
    }

    /// Deletes the acknowledged notifications, returning a list of status code for each according
    /// to whether it was found or not.
    ///
    /// Good - deleted notification
    /// BadSubscriptionIdInvalid - Subscription doesn't exist
    /// BadSequenceNumberUnknown - Sequence number doesn't exist
    ///
    fn process_subscription_acknowledgements(&mut self, request: &PublishRequestEntry) -> Option<Vec<StatusCode>> {
        trace!("Processing subscription acknowledgements");
        let request = &request.request;
        if request.subscription_acknowledgements.is_some() {
            let subscription_acknowledgements = request.subscription_acknowledgements.as_ref().unwrap();
            let results = subscription_acknowledgements.iter().map(|subscription_acknowledgement| {
                let subscription_id = subscription_acknowledgement.subscription_id;
                let subscription = self.subscriptions.get_mut(&subscription_id);
                if subscription.is_none() {
                    BadSubscriptionIdInvalid
                } else {
                    subscription.unwrap().delete_acked_notification_msg(subscription_acknowledgement)
                }
            }).collect();
            Some(results)
        } else {
            None
        }
    }
}