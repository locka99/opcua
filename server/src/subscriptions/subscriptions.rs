use std::collections::{BTreeMap, VecDeque};

use time;
use chrono;

use opcua_types::*;
use opcua_types::status_codes::StatusCode;
use opcua_types::status_codes::StatusCode::*;
use opcua_types::service_types::{PublishRequest, ServiceFault, ResponseHeader, NotificationMessage};
use opcua_types::SupportedMessage::PublishResponse;

use constants;

use DateTimeUtc;
use address_space::types::AddressSpace;
use subscriptions::{PublishRequestEntry, PublishResponseEntry};
use subscriptions::subscription::{Subscription, SubscriptionState, TickReason};


/// Subscription events are passed between the timer thread and the session thread so must
/// be transferable
#[derive(Clone, Debug, PartialEq)]
pub enum SubscriptionEvent {
    PublishResponses(Vec<PublishResponseEntry>),
}


pub struct Subscriptions {
    /// The publish request queue (requests by the client on the session)
    pub publish_request_queue: VecDeque<PublishRequestEntry>,
    /// The publish response queue
    pub publish_response_queue: VecDeque<PublishResponseEntry>,
    // Timeout period for requests in ms
    publish_request_timeout: i64,
    /// Subscriptions associated with the session
    subscriptions: BTreeMap<UInt32, Subscription>,
    /// Maximum number of publish requests
    max_publish_requests: usize,
    /// Maximum number of items in the retransmission queue
    max_retransmission_queue: usize,
    // Notifications waiting to be sent - subscription id and notification message.
    transmission_queue: VecDeque<(UInt32, NotificationMessage)>,
    // Notifications that have been sent but have yet to be acknowledged (retransmission queue).
    // Key is sequence number. Value is subscription id and notification message
    retransmission_queue: BTreeMap<UInt32, (UInt32, NotificationMessage)>,
    /// The value that records the value of the sequence number used in NotificationMessages.
    last_sequence_number: UInt32,
}

impl Subscriptions {
    pub fn new(max_publish_requests: usize, publish_request_timeout: i64) -> Subscriptions {
        Subscriptions {
            publish_request_queue: VecDeque::with_capacity(max_publish_requests),
            publish_response_queue: VecDeque::with_capacity(max_publish_requests),
            publish_request_timeout,
            subscriptions: BTreeMap::new(),
            max_publish_requests,
            last_sequence_number: 0,
            max_retransmission_queue: max_publish_requests * 2,
            transmission_queue: VecDeque::new(),
            retransmission_queue: BTreeMap::new(),
        }
    }

    /// Places a new publish request onto the queue of publish requests.
    ///
    /// If the queue is full this call will pop the oldest and generate a service fault
    /// for that before pushing the new one.
    pub fn enqueue_publish_request(&mut self, _: &AddressSpace, request_id: UInt32, request: PublishRequest) -> Result<(), StatusCode> {
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

    /// The tick causes the subscription manager to iterate through individual subscriptions calling tick
    /// on each in order of priority. In each case this could generate data change notifications. Data change
    /// notifications will be attached to the next available publish response and queued for sending
    /// to the client.
    pub fn tick(&mut self, address_space: &AddressSpace, tick_reason: TickReason) -> Result<(), StatusCode> {
        let now = chrono::Utc::now();

        let subscription_ids = {
            let mut subscription_priority: Vec<(u32, u8)> = self.subscriptions.values().map(|v| (v.subscription_id, v.priority)).collect();
            subscription_priority.sort_by(|s1, s2| s1.1.cmp(&s2.1));
            subscription_priority.iter().map(|s| s.0).collect::<Vec<u32>>()
        };

        // Iterate through all subscriptions. If there is a publish request it will be used to
        // acknowledge notifications and the response to return new notifications.

        let mut publish_request_len = self.publish_request_queue.len();

        // Now tick over the subscriptions
        subscription_ids.iter().for_each(|subscription_id| {
            let subscription_state = {
                let subscription = self.subscriptions.get(subscription_id).unwrap();
                subscription.state
            };
            if subscription_state == SubscriptionState::Closed {
                // Subscription is dead so remove it
                self.subscriptions.remove(&subscription_id);
            } else {
                let subscription = self.subscriptions.get_mut(subscription_id).unwrap();
                let publishing_req_queued = publish_request_len > 0;

                // Now tick the subscription to see if it has any notifications. If there are
                // notifications then the publish response will be associated with his subscription
                // and ready to go.

                let notification_message = subscription.tick(address_space, tick_reason, publishing_req_queued, &now);
                if let Some(notification_message) = notification_message {
                    self.transmission_queue.push_front((*subscription_id, notification_message));
                    if publish_request_len > 0 {
                        publish_request_len -= 1;
                    }
                }
            }
        });

        // Now for each publish request, produce a publish response for each notification message waiting

        let mut handled_requests = Vec::with_capacity(self.publish_request_queue.len());
        let mut publish_responses = Vec::with_capacity(self.publish_request_queue.len());

        // Extract notification message with the next available publish request

        // TODO
        if !self.publish_request_queue.is_empty() {

            // Iterate through all publish requests or until transmission queue is empty
            while !self.transmission_queue.is_empty() {
                if self.publish_request_queue.is_empty() {
                    break;
                }

                let publish_request = self.publish_request_queue.pop_back().unwrap();

                // Get the oldest notification to send
                let (subscription_id, notification_message) = self.transmission_queue.pop_back().unwrap();
                self.retransmission_queue.insert(notification_message.sequence_number, (subscription_id, notification_message.clone()));

                let available_sequence_numbers = self.available_sequence_numbers();
                let response = self.make_publish_response(publish_request, now, notification_message, available_sequence_numbers);

                self.publish_response_queue.push_front(response);
            }

            // Remove old notifications which were unacknowledged
            self.remove_old_unknowledged_notifications();
        }

        Ok(())
    }

    /// Deletes the acknowledged notifications, returning a list of status code for each according
    /// to whether it was found or not.
    ///
    /// Good - deleted notification
    /// BadSubscriptionIdInvalid - Subscription doesn't exist
    /// BadSequenceNumberUnknown - Sequence number doesn't exist
    ///
    fn process_subscription_acknowledgements(&mut self, request: &PublishRequest) -> Option<Vec<StatusCode>> {
        trace!("Processing subscription acknowledgements");
        if let Some(ref subscription_acknowledgements) = request.subscription_acknowledgements {
            let results = subscription_acknowledgements.iter().map(|subscription_acknowledgement| {
                let subscription_id = subscription_acknowledgement.subscription_id;
                let sequence_number = subscription_acknowledgement.sequence_number;
                // Check the subscription id exists
                if let Some(subscription) = self.subscriptions.get(&subscription_id) {
                    // Clear notification by its sequence number
                    if self.retransmission_queue.remove(&sequence_number).is_some() {
                        Good
                    } else {
                        error!("Can't find acknowledged notification with sequence number {}", sequence_number);
                        BadSequenceNumberUnknown
                    }
                } else {
                    error!("Can't find acknowledged notification subscription id {}", subscription_id);
                    BadSubscriptionIdInvalid
                }
            }).collect();
            Some(results)
        } else {
            None
        }
    }

    /// Returns the array of available sequence numbers
    fn available_sequence_numbers(&self) -> Option<Vec<UInt32>> {
        if self.retransmission_queue.is_empty() {
            None
        } else {
            Some(self.retransmission_queue.keys().cloned().collect())
        }
    }

    fn make_publish_response(&self, publish_request: &PublishRequestEntry, now: &DateTime, notification_message: NotificationMessage, available_sequence_numbers: Option<Vec<UInt32>>) -> PublishResponseEntry {
        PublishResponseEntry {
            request_id: publish_request.request_id,
            response: SupportedMessage::PublishResponse(PublishResponse {
                response_header: ResponseHeader::new_timestamped_service_result(now.clone(), &publish_request.request.request_header, Good),
                subscription_id: self.subscription_id,
                available_sequence_numbers,
                more_notifications: self.more_notifications,
                notification_message,
                results: None,
                diagnostic_infos: None,
            }),
        }
    }

    /// Return the next sequence number
    fn create_sequence_number(&mut self) -> UInt32 {
        self.last_sequence_number += 1;
        // Sequence number should wrap if it exceeds this value - part 6
        if self.last_sequence_number > constants::SEQUENCE_NUMBER_WRAPAROUND {
            self.last_sequence_number = 1;
        }
        self.last_sequence_number
    }

    /// Finds a notification message in the retransmission queue matching the supplied subscription id
    /// and sequence number. Returns `BadNoSubscription` or `BadMessageNotAvailable` if a matching
    /// notification is not found.
    pub fn find_notification_message(&self, subscription_id: UInt32, sequence_number: UInt32) -> Result<NotificationMessage, StatusCode> {
        // Look for the subscription
        if let Some(ref subscription) = self.subscriptions.get(&subscription_id) {
            // Look for the sequence number
            if let Some(ref notification_message) = self.retransmission_queue.get(&sequence_number) {
                Some(notification_message.1.clone())
            } else {
                Err(StatusCode::BadMessageNotAvailable)
            }
        } else {
            Err(StatusCode::BadNoSubscription)
        }
    }

    /// Purges notifications waiting for acknowledgement if they exceed the max retransmission queue
    /// size.
    fn remove_old_unknowledged_notifications(&mut self) {
        if self.retransmission_queue.len() <= self.max_retransmission_queue {
            return;
        }

        // Compare number of items in retransmission queue to max permissible and remove the older
        // notifications.
        let mut remove_count = self.retransmission_queue.len() - self.max_retransmission_queue;
        let mut sequence_numbers_to_remove = Vec::with_capacity(remove_count);

        // BTree means these should iterate in order of insertion, i.e. oldest first
        for (idx, (k, _)) in self.retransmission_queue.iter().enumerate() {
            if idx > remove_count {
                break;
            }
            sequence_numbers_to_remove.push(*k);
        }
        sequence_numbers_to_remove.for_each(|k| self.retransmission_queue.remove(&k));
    }
}